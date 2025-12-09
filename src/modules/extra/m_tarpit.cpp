/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 * Copyright (C) 2024 Allen Day
 *
 * This file is part of InspIRCd.  InspIRCd is free software: you can
 * redistribute it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "inspircd.h"
#include "numerichelper.h"
#include "timeutils.h"
#include "xline.h"
#include "extension.h"
#include "modules/extra/tarpit_metrics.h"
#include <array>
#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstdlib>
#include <deque>
#include <limits>
#include <vector>

#ifdef USE_SYSTEM_UTFCPP
# include <utf8cpp/utf8.h>
#else
# include <utfcpp/core.h>
#endif

namespace
{
	enum class SpamAction : uint8_t
	{
		DELAY,
		BLOCK,
		GLINE,
		SILENT
	};

	struct KmerData final
	{
		unsigned int frequency = 0;
		time_t last_seen = 0;
	};

	struct ReputationEntry final
	{
		double score = 0.0;
		time_t last_seen = 0;
	};

	struct TarpitMessage final
	{
		std::string command;
		std::string target;
		std::string message;
		time_t release = 0;
	};

	struct FanoutHit final
	{
		std::string target;
		time_t time = 0;
	};

	struct UserStats final
	{
		size_t early_messages = 0;
		size_t early_totalkmers = 0;
		insp::flat_set<std::string> early_distinct;
		double early_weight_sum = 0.0;
		time_t tarpit_until = 0;
		unsigned long last_delay = 0;
		bool bypass = false;
		std::deque<TarpitMessage> queue;
		std::deque<FanoutHit> fanout_recent;
		insp::flat_map<std::string, size_t> fanout_counts;
		time_t connected = 0;
	};

	bool IsZeroWidth(uint32_t cp)
	{
		switch (cp)
		{
			case 0x00AD:
			case 0x180E:
			case 0x200B:
			case 0x200C:
			case 0x200D:
			case 0x2060:
			case 0xFEFF:
				return true;
		}
		return false;
	}
}

class ModuleTarpit;

class CommandTarpit final
	: public Command
{
	ModuleTarpit& parent;

public:
	CommandTarpit(ModuleTarpit& mod);

	CmdResult Handle(User* user, const Params& params) override;
	void SendHelp(User* user);
};

class ModuleTarpit final
	: public Module
{
private:
	struct Preset final
	{
		const char* name;
		unsigned long delay;
		double multiplier;
		unsigned long maxdelay;
		double spammy_threshold;
		double early_ratio;
		double early_weight;
		unsigned long fanout_window;
		double fanout_delay;
		double fanout_multiplier;
		double kmer_penalty;
		unsigned long kmer_penalty_cap;
		double kmer_penalty_min_ratio;
		double kmer_penalty_min_score;
		unsigned long reputation_ttl;
		double interaction_low_weight;
		double interaction_spammy_weight;
		double interaction_penalty_weight;
		unsigned int interaction_min_signals;
		double interaction_exponent;
		unsigned long trust_decay;
		double trust_weight;
	};

	static constexpr Preset presets[5] = {
		{ "monitor", 1, 1.0, 60, 0.90, 0.70, 12.0, 0,   0.0, 1.0, 0.00,  0, 0.95, 10.0, 1200, 0.0, 0.0, 0.0, 3, 1.0, 0, 0.0 },
		{ "low",     1, 1.05,120, 0.75, 0.60, 10.5,30,  0.25,1.35,0.02, 30, 0.75, 5.0,  900, 0.4, 0.7, 0.3, 2, 1.25,240, 0.4 },
		{ "medium",  1, 1.10,300, 0.60, 0.50,  9.8,45,  0.50,1.50,0.05, 60, 0.60, 3.0,  600, 0.9, 1.3, 0.8, 2, 1.5, 450, 0.6 },
		{ "high",    2, 1.15,300, 0.50, 0.45,  9.4,60,  1.50,2.50,0.10, 90, 0.50, 2.0,  450, 1.1, 1.7, 1.1, 2, 1.7, 900, 0.9 },
		{ "extreme", 3, 1.20,300, 0.40, 0.40,  9.0,60,  3.0, 4.0, 0.20,120, 0.40, 1.0,  300, 1.2, 1.9, 1.2, 2, 1.8, 1200, 1.2 }
	};

	struct LevelSettings final
	{
		SpamAction action = SpamAction::DELAY;
		size_t kmersize = 4;
		size_t minlength = 12;
		size_t earlymaxmessages = 10;
		double earlyratio = 0.35;
		double earlyweight = 9.2;
		double spammythreshold = 0.30;
		size_t maxcachesize = 100000;
		unsigned long cachettl = 600;
		unsigned long reputationttl = 900;
		size_t warmupobservations = 5000;
		double tarpitdelay = 4;
		double tarpitmultiplier = 1.1;
		unsigned long tarpitmaxdelay = 300;
		double fanoutdelay = 1.0;
		double fanoutmultiplier = 2.0;
		unsigned long fanoutwindow = 30;
		double kmerpenalty = 0.05;
		unsigned long kmerpenaltycap = 60;
		double kmerpenaltyminratio = 0.6;
		double kmerpenaltyminscore = 3.0;
		unsigned long glineduration = 3600;
		std::string exemptmodes = "CoaA";
		std::string trustedmodes = "Vr";
		double interactionlowweight = 0.0;
		double interactionspammyweight = 0.0;
		double interactionpenaltyweight = 0.0;
		unsigned int interactionminsignals = 2;
		double interactionexponent = 1.0;
		unsigned long trustdecay = 0;
		double trustweight = 0.0;
		double feedbackpositive = 10.0;
		double feedbacknegative = 10.0;
	};

	struct StatSample final
	{
		time_t ts = 0;
		unsigned long delay = 0;
		bool dropped = false;
		std::string reason;
	};

	insp::flat_map<std::string, KmerData> cache;
	insp::flat_map<std::string, ReputationEntry> reputation;
	SimpleExtItem<UserStats> userstats;

	SpamAction action = SpamAction::DELAY;
	unsigned int currentlevel = 2;

	size_t kmersize = 4;
	size_t minlength = 12;
	size_t earlymaxmessages = 10;
	double earlyratio = 0.35;
	double earlyweight = 9.2;
	double spammythreshold = 0.30;
	size_t maxcachesize = 100000;
	unsigned long cachettl = 600;
	unsigned long reputationttl = 900;
	size_t warmupobservations = 5000;

	double tarpitdelay = 4;
	double tarpitmultiplier = 1.1;
	unsigned long tarpitmaxdelay = 300;
	double fanoutdelay = 1.0;
	double fanoutmultiplier = 2.0;
	unsigned long fanoutwindow = 30;
	double kmerpenalty = 0.05;
	unsigned long kmerpenaltycap = 60;
	double kmerpenaltyminratio = 0.6;
	double kmerpenaltyminscore = 3.0;

	unsigned long glineduration = 3600;
	unsigned long totalobservations = 0;
	unsigned long long totalprocessed = 0;
	std::string exemptmodes = "CoaA";
	std::string trustedmodes = "Vr";
	time_t lastcachecleanup = 0;
	time_t lastreputationcleanup = 0;

	unsigned long long totalinspected = 0;
	unsigned long long totaldelayed = 0;
	unsigned long long totaldropped = 0;
	unsigned long long totaldelay = 0;
	std::deque<StatSample> recentevents;
	insp::flat_map<std::string, unsigned long> reasoncounts;
	unsigned long statseventwindow = 900;
	size_t statseventmax = 1000;
	bool warmupannounced = false;
	std::deque<time_t> inspectedhistory;

	CommandTarpit command;
	MetricsProvider metricsprovider;
	std::array<LevelSettings, std::size(presets)> levelsettings;
	double interactionlowweight = 0.0;
	double interactionspammyweight = 0.0;
	double interactionpenaltyweight = 0.0;
	unsigned int interactionminsignals = 2;
	double interactionexponent = 1.0;
	unsigned long trustdecay = 0;
	double trustweight = 0.0;
	double feedbackpositive = 10.0;
	double feedbacknegative = 10.0;
	const double feedbackmaxscore = 100.0;

	friend class TarpitMetricsService;

	class MetricsProvider final
		: public TarpitMetricsProvider
	{
		ModuleTarpit& parent;

	public:
		MetricsProvider(ModuleTarpit* mod)
			: TarpitMetricsProvider(mod)
			, parent(*mod)
		{
		}

		bool GetStats(TarpitMetrics& out, unsigned long window = 0) override
		{
			out = {};
			out.total_processed = parent.totalprocessed;
			out.total_delayed = parent.totaldelayed;
			out.total_dropped = parent.totaldropped;
			out.total_delay = parent.totaldelay;
			out.current_level = parent.currentlevel;

			time_t cutoff = (window ? (ServerInstance->Time() - static_cast<time_t>(window)) : 0);
			unsigned long long windowdelays = 0;
			unsigned long long windowdrops = 0;
			unsigned long long windowdelaytotal = 0;
			unsigned long long windowprocessed = 0;

			for (auto it = parent.recentevents.rbegin(); it != parent.recentevents.rend(); ++it)
			{
				if (cutoff && it->ts < cutoff)
					break;
				if (it->dropped)
					++windowdrops;
				else
				{
					++windowdelays;
					windowdelaytotal += it->delay;
				}
			}

			if (window)
			{
				for (auto it = parent.inspectedhistory.rbegin(); it != parent.inspectedhistory.rend(); ++it)
				{
					if (cutoff && *it < cutoff)
						break;
					++windowprocessed;
				}
			}

			if (!window)
			{
				windowprocessed = out.total_processed;
				windowdelays = out.total_delayed;
				windowdrops = out.total_dropped;
				windowdelaytotal = out.total_delay;
			}

			out.window_processed = windowprocessed;
			out.window_delayed = windowdelays;
			out.window_dropped = windowdrops;
			out.window_delay = windowdelaytotal;
			return true;
		}
	};

public:
	ModuleTarpit()
		: Module(VF_VENDOR, "Detects duplicate private-message spam using k-mer fingerprints.")
		, userstats(this, "tarpit-stats", ExtensionType::USER, true)
		, command(*this)
		, metricsprovider(this)
	{
		for (unsigned int i = 0; i < levelsettings.size(); ++i)
			levelsettings[i] = BuildDefaultSettings(i);
	}

	void ReadConfig(ConfigStatus& status) override
	{
		ResetLevelSettings();

		unsigned int requestedlevel = std::min(currentlevel, static_cast<unsigned int>(levelsettings.size() - 1));
		const auto tags = ServerInstance->Config->ConfTags("tarpit");
		for (auto it = tags.begin(); it != tags.end(); ++it)
		{
			const std::shared_ptr<ConfigTag>& tag = it->second;
			statseventwindow = tag->getDuration("stats_window", statseventwindow, 60, 7200);
			statseventmax = tag->getNum<size_t>("stats_max_events", statseventmax, 10, 5000);
			const unsigned int lvl = tag->getNum<unsigned int>("level", std::numeric_limits<unsigned int>::max(), 0, static_cast<unsigned int>(levelsettings.size() - 1));
			if (lvl >= levelsettings.size())
				throw ModuleException(this, "<tarpit> tags must include level=\"0-4\"");

			OverrideSettings(levelsettings[lvl], tag);
			if (tag->getBool("default", false))
				requestedlevel = lvl;
		}

		ApplyPreset(requestedlevel, false);
		warmupannounced = (warmupobservations == 0);
	}

	ModResult OnUserPreMessage(User* user, MessageTarget& target, MessageDetails& details) override
	{
		LocalUser* local = IS_LOCAL(user);
		if (!local)
			return MOD_RES_PASSTHRU;

		if (HasListedMode(local, exemptmodes) || HasListedMode(local, trustedmodes))
			return MOD_RES_PASSTHRU;

		if (target.type != MessageTarget::TYPE_USER)
			return MOD_RES_PASSTHRU;

		++totalprocessed;
		UserStats* stats = GetStats(local);
		if (stats->bypass)
		{
			stats->bypass = false;
			return MOD_RES_PASSTHRU;
		}

		const std::string normalized = NormalizeText(details.text);
		if (normalized.length() < minlength || normalized.length() < kmersize)
			return MOD_RES_PASSTHRU;

		const std::vector<std::string> kmers = ExtractKmers(normalized);
		if (kmers.empty())
			return MOD_RES_PASSTHRU;

		const time_t now = ServerInstance->Time();
		++totalinspected;

		if (totalobservations < warmupobservations)
		{
			UpdateCache(kmers, now);
			if (!warmupannounced && warmupobservations && totalobservations >= warmupobservations)
			{
				warmupannounced = true;
				ServerInstance->Logs.Normal(MODNAME, "m_tarpit warm-up complete ({} observations)", warmupobservations);
			}
			return MOD_RES_PASSTHRU;
		}

		const double msgweight = CalculateMessageWeight(kmers);
		const double spammy_ratio = CalculateSpammyRatio(kmers, now);

		UpdateEarlyStats(*stats, kmers, msgweight);
		const double ratio = GetEntropyRatio(*stats);
		const double weightavg = GetWeightAverage(*stats, msgweight);

		UpdateCache(kmers, now);
		inspectedhistory.push_back(now);
		while (!inspectedhistory.empty() && (now - inspectedhistory.front()) > static_cast<time_t>(statseventwindow))
			inspectedhistory.pop_front();

		const bool earlytrip = (stats->early_messages <= earlymaxmessages)
			&& (ratio < earlyratio) && (weightavg < earlyweight);
		const bool reputationtrip = (spammy_ratio > spammythreshold);

		User* dest = target.Get<User>();
		const std::string destnick = dest ? dest->nick : "";
		const unsigned long fanoutbonus = CalculateFanoutPenalty(*stats, destnick, now);
		const bool fanouttrip = (fanoutbonus > 0);
		const unsigned long kmerbonus = CalculateKmerPenalty(kmers, spammy_ratio, now);
		const bool kmertrip = (kmerbonus > 0);
		const double interactionboost = CalculateInteractionBoost(earlytrip, reputationtrip, kmertrip);
		const double trustboost = CalculateTrustBoost(*stats, now);
		const double totalboost = interactionboost * trustboost;

		bool shoulddelay = (now < stats->tarpit_until) || earlytrip || reputationtrip || fanouttrip || kmertrip;
		if (!shoulddelay)
			return MOD_RES_PASSTHRU;

		if (earlytrip)
			MarkKmersSpammy(kmers, now);

		if (action != SpamAction::DELAY)
		{
			HandleDetection(local, target, normalized);
			return MOD_RES_DENY;
		}

		bool dropped = false;
		const unsigned long delay = QueueMessage(*stats, local, target, details, now, totalboost, fanoutbonus, kmerbonus, dropped);

		std::string reason;
		if (earlytrip)
			reason = "low-entropy";
		if (reputationtrip)
		{
			if (!reason.empty())
				reason += "+";
			reason += "spammy-kmer";
		}
		if (kmertrip)
		{
			if (!reason.empty())
				reason += "+";
			reason += "kmer-penalty";
		}
		if (fanouttrip)
		{
			if (!reason.empty())
				reason += "+";
			reason += "fanout";
		}
		if (reason.empty())
			reason = (now < stats->tarpit_until ? "repeat-delay" : "heuristic");

		const std::string interactionnote = (totalboost > 1.01 ? INSP_FORMAT(" interaction={:.2f}x", totalboost) : "");
		if (dropped)
		{
			++totaldropped;
			RecordEvent(true, delay, reason);
			ServerInstance->Logs.Normal(MODNAME, "Dropping {} -> {} (reason={}{} exceeded tarpit_max={}s ratio={:.3f} weight={:.3f} spammy={:.3f} text='{}')",
				user->nick, destnick, reason, interactionnote, tarpitmaxdelay, ratio, weightavg, spammy_ratio, details.text);
			return MOD_RES_DENY;
		}

		++totaldelayed;
		totaldelay += delay;
		RecordEvent(false, delay, reason);
		ServerInstance->Logs.Normal(MODNAME, "Tarpitting {} -> {} for {}s (reason={}{} ratio={:.3f} weight={:.3f} spammy={:.3f} text='{}')",
			user->nick, destnick, delay, reason, interactionnote, ratio, weightavg, spammy_ratio, details.text);

		return MOD_RES_DENY;
	}

	void OnBackgroundTimer(time_t curtime) override
	{
		CleanupCache(curtime);
		CleanupReputation(curtime);
		ProcessQueues(curtime);
	}

	void OnUserDisconnect(LocalUser* user) override
	{
		auto* stats = userstats.Get(user);
		if (stats)
			stats->queue.clear();
	}

	void SendStats(User* user, unsigned long window)
	{
		if (!user->IsOper())
			return;

		const time_t cutoff = (window ? (ServerInstance->Time() - window) : 0);

		unsigned long windowdelays = 0;
		unsigned long windowdrops = 0;
		unsigned long long windowprocessed = 0;
		unsigned long long windowdelaytotal = 0;
		insp::flat_map<std::string, unsigned long> windowreasons;

		for (auto it = recentevents.rbegin(); it != recentevents.rend(); ++it)
		{
			if (cutoff && it->ts < cutoff)
				break;
			if (it->dropped)
				++windowdrops;
			else
			{
				++windowdelays;
				windowdelaytotal += it->delay;
			}
			++windowreasons[it->reason];
		}

		if (window)
		{
			for (auto it = inspectedhistory.rbegin(); it != inspectedhistory.rend(); ++it)
			{
				if (cutoff && *it < cutoff)
					break;
				++windowprocessed;
			}
		}

		auto formatline = [](const std::string& label, unsigned long long processed, unsigned long long delayed, unsigned long long dropped, unsigned long long delaytotal)
		{
			double avgdelay = (delayed ? static_cast<double>(delaytotal) / static_cast<double>(delayed) : 0.0);
			double delaypct = (processed ? (static_cast<double>(delayed) / static_cast<double>(processed)) * 100.0 : 0.0);
			double droppct = (processed ? (static_cast<double>(dropped) / static_cast<double>(processed)) * 100.0 : 0.0);
			return INSP_FORMAT("{} processed={} delayed={} ({:.2f}%) dropped={} ({:.2f}%) avg_delay={:.2f}s",
				label, processed, delayed, delaypct, dropped, droppct, avgdelay);
		};

		user->WriteNotice(INSP_FORMAT("TARPIT: level={} ({}) {}", currentlevel, presets[currentlevel].name,
			formatline("total", totalprocessed, totaldelayed, totaldropped, totaldelay)));

		if (window)
		{
			user->WriteNotice(INSP_FORMAT("TARPIT: {}", formatline(INSP_FORMAT("last {}s", window), windowprocessed, windowdelays, windowdrops, windowdelaytotal)));
			if (!windowreasons.empty())
			{
				const unsigned long totalwindowevents = windowdelays + windowdrops;
				std::vector<std::pair<std::string, unsigned long>> sortedreasons(windowreasons.begin(), windowreasons.end());
				std::sort(sortedreasons.begin(), sortedreasons.end(), [](const auto& lhs, const auto& rhs)
				{
					return lhs.second > rhs.second;
				});
				for (const auto& [reason, count] : sortedreasons)
				{
					double pct = (totalwindowevents ? (static_cast<double>(count) / static_cast<double>(totalwindowevents)) * 100.0 : 0.0);
					user->WriteNotice(INSP_FORMAT("TARPIT: {:+07.2f}% {:>5} {}", pct, count, reason));
				}
			}
		}
	}

	void SendConfig(User* user, const std::string& key)
	{
		if (!user->IsOper())
			return;

		if (key.empty())
		{
			user->WriteNotice(INSP_FORMAT("TARPIT config: level={} ({}) delay={:.2f}s multiplier={:.2f} max_delay={}s spammy_threshold={:.2f} early_ratio={:.2f} fanout_delay={:.2f} fanout_multiplier={:.2f} fanout_window={}s kmer_penalty={:.2f} kmer_cap={}s",
				currentlevel, presets[currentlevel].name, tarpitdelay, tarpitmultiplier, tarpitmaxdelay,
				spammythreshold, earlyratio, fanoutdelay, fanoutmultiplier, fanoutwindow, kmerpenalty, kmerpenaltycap));
			return;
		}

		std::string lower = key;
		std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
		std::string value;
		if (lower == "level")
			value = ConvToStr(currentlevel);
		else if (lower == "k")
			value = ConvToStr(kmersize);
		else if (lower == "delay")
			value = ConvToStr(tarpitdelay);
		else if (lower == "multiplier")
			value = ConvToStr(tarpitmultiplier);
		else if (lower == "max_delay")
			value = ConvToStr(tarpitmaxdelay);
		else if (lower == "spammy_threshold")
			value = ConvToStr(spammythreshold);
		else if (lower == "early_ratio")
			value = ConvToStr(earlyratio);
		else if (lower == "fanout_delay")
			value = ConvToStr(fanoutdelay);
		else if (lower == "fanout_multiplier")
			value = ConvToStr(fanoutmultiplier);
		else if (lower == "fanout_window")
			value = ConvToStr(fanoutwindow);
		else if (lower == "kmer_penalty")
			value = ConvToStr(kmerpenalty);
		else if (lower == "kmer_penalty_cap")
			value = ConvToStr(kmerpenaltycap);
		else if (lower == "kmer_penalty_min_ratio")
			value = ConvToStr(kmerpenaltyminratio);
		else if (lower == "kmer_penalty_min_score")
			value = ConvToStr(kmerpenaltyminscore);
		else if (lower == "interaction_low_weight")
			value = ConvToStr(interactionlowweight);
		else if (lower == "interaction_spammy_weight")
			value = ConvToStr(interactionspammyweight);
		else if (lower == "interaction_penalty_weight")
			value = ConvToStr(interactionpenaltyweight);
		else if (lower == "interaction_min_signals")
			value = ConvToStr(interactionminsignals);
		else if (lower == "interaction_exponent")
			value = ConvToStr(interactionexponent);
		else if (lower == "stats_window")
			value = ConvToStr(statseventwindow);
		else if (lower == "stats_max_events")
			value = ConvToStr(statseventmax);
		else if (lower == "feedback_positive")
			value = ConvToStr(feedbackpositive);
		else if (lower == "feedback_negative")
			value = ConvToStr(feedbacknegative);
		else
		{
			user->WriteNotice("TARPIT: Unknown config key " + key);
			return;
		}

		user->WriteNotice("TARPIT: " + lower + " = " + value);
	}

	bool SetConfig(User* user, const std::string& key, const std::string& value)
	{
		if (!user->IsOper())
			return false;

		std::string lower = key;
		std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
		try
		{
			if (lower == "level")
			{
				unsigned long parsed = 0;
				if (!ParseUnsigned(value, parsed))
					throw ModuleException(this, "invalid level");
				unsigned int lvl = static_cast<unsigned int>(parsed);
				if (lvl >= std::size(presets))
					throw ModuleException(this, "invalid level");
				ApplyPreset(lvl, true);
				ServerInstance->SNO.WriteGlobalSno('a', "m_tarpit: {} set level {} ({}).", user->nick, lvl, presets[lvl].name);
				user->WriteNotice(INSP_FORMAT("TARPIT: {} set to {}", lower, lvl));
				return true;
			}
			else if (lower == "k")
			{
				SetNumeric(user, kmersize, value, 3.0, 6.0, "k");
				CurrentLevelSettings().kmersize = kmersize;
			}
			else if (lower == "delay")
			{
				SetNumeric(user, tarpitdelay, value, 1.0, 600.0, "delay");
				CurrentLevelSettings().tarpitdelay = tarpitdelay;
			}
			else if (lower == "multiplier")
			{
				SetNumeric(user, tarpitmultiplier, value, 1.0, 10.0, "multiplier");
				CurrentLevelSettings().tarpitmultiplier = tarpitmultiplier;
			}
			else if (lower == "max_delay")
			{
				SetNumeric(user, tarpitmaxdelay, value, 0.0, 86400.0, "max delay");
				CurrentLevelSettings().tarpitmaxdelay = tarpitmaxdelay;
			}
			else if (lower == "spammy_threshold")
			{
				SetNumeric(user, spammythreshold, value, 0.0, 1.0, "spammy threshold");
				CurrentLevelSettings().spammythreshold = spammythreshold;
			}
			else if (lower == "early_ratio")
			{
				SetNumeric(user, earlyratio, value, 0.0, 1.0, "early ratio");
				CurrentLevelSettings().earlyratio = earlyratio;
			}
			else if (lower == "fanout_delay")
			{
				SetNumeric(user, fanoutdelay, value, 0.0, 60.0, "fanout delay");
				CurrentLevelSettings().fanoutdelay = fanoutdelay;
			}
			else if (lower == "fanout_multiplier")
			{
				SetNumeric(user, fanoutmultiplier, value, 1.0, 10.0, "fanout multiplier");
				CurrentLevelSettings().fanoutmultiplier = fanoutmultiplier;
			}
			else if (lower == "fanout_window")
			{
				SetNumeric(user, fanoutwindow, value, 0.0, 600.0, "fanout window");
				CurrentLevelSettings().fanoutwindow = fanoutwindow;
			}
			else if (lower == "kmer_penalty")
			{
				SetNumeric(user, kmerpenalty, value, 0.0, 3600.0, "k-mer penalty");
				CurrentLevelSettings().kmerpenalty = kmerpenalty;
			}
			else if (lower == "kmer_penalty_cap")
			{
				SetNumeric(user, kmerpenaltycap, value, 0.0, 86400.0, "k-mer cap");
				CurrentLevelSettings().kmerpenaltycap = kmerpenaltycap;
			}
			else if (lower == "kmer_penalty_min_ratio")
			{
				SetNumeric(user, kmerpenaltyminratio, value, 0.0, 1.0, "k-mer min ratio");
				CurrentLevelSettings().kmerpenaltyminratio = kmerpenaltyminratio;
			}
			else if (lower == "kmer_penalty_min_score")
			{
				SetNumeric(user, kmerpenaltyminscore, value, 0.0, 1000.0, "k-mer min score");
				CurrentLevelSettings().kmerpenaltyminscore = kmerpenaltyminscore;
			}
			else if (lower == "interaction_low_weight")
			{
				SetNumeric(user, interactionlowweight, value, 0.0, 10.0, "interaction low weight");
				CurrentLevelSettings().interactionlowweight = interactionlowweight;
			}
			else if (lower == "interaction_spammy_weight")
			{
				SetNumeric(user, interactionspammyweight, value, 0.0, 10.0, "interaction spammy weight");
				CurrentLevelSettings().interactionspammyweight = interactionspammyweight;
			}
			else if (lower == "interaction_penalty_weight")
			{
				SetNumeric(user, interactionpenaltyweight, value, 0.0, 10.0, "interaction penalty weight");
				CurrentLevelSettings().interactionpenaltyweight = interactionpenaltyweight;
			}
			else if (lower == "interaction_min_signals")
			{
				unsigned long parsed = 0;
				if (!ParseUnsigned(value, parsed) || parsed < 1 || parsed > 3)
					throw ModuleException(this, "invalid interaction_min_signals");
				interactionminsignals = static_cast<unsigned int>(parsed);
				CurrentLevelSettings().interactionminsignals = interactionminsignals;
			}
			else if (lower == "interaction_exponent")
			{
				SetNumeric(user, interactionexponent, value, 0.5, 5.0, "interaction exponent");
				CurrentLevelSettings().interactionexponent = interactionexponent;
			}
			else if (lower == "stats_window")
			{
				unsigned long parsed = 0;
				if (!ParseUnsigned(value, parsed) || parsed < 60 || parsed > 7200)
					throw ModuleException(this, "invalid stats window");
				statseventwindow = parsed;
			}
			else if (lower == "stats_max_events")
			{
				unsigned long parsed = 0;
				if (!ParseUnsigned(value, parsed) || parsed < 10 || parsed > 5000)
					throw ModuleException(this, "invalid stats max events");
				statseventmax = static_cast<size_t>(parsed);
			}
			else if (lower == "feedback_positive")
			{
				SetNumeric(user, feedbackpositive, value, 0.0, 100.0, "feedback positive");
				CurrentLevelSettings().feedbackpositive = feedbackpositive;
			}
			else if (lower == "feedback_negative")
			{
				SetNumeric(user, feedbacknegative, value, 0.0, 100.0, "feedback negative");
				CurrentLevelSettings().feedbacknegative = feedbacknegative;
			}
			else
			{
				user->WriteNotice("TARPIT: Unknown key " + key);
				return false;
			}
		}
		catch (const ModuleException&)
		{
			user->WriteNotice("TARPIT: Invalid value for " + key);
			return false;
		}

		ServerInstance->SNO.WriteGlobalSno('a', "m_tarpit: {} set {} to {}", user->nick, lower, value);
		user->WriteNotice(INSP_FORMAT("TARPIT: {} set to {}", lower, value));
		return true;
	}

private:
	void RecordEvent(bool dropped, unsigned long delay, const std::string& reason)
	{
		StatSample sample;
		sample.ts = ServerInstance->Time();
		sample.delay = delay;
		sample.dropped = dropped;
		sample.reason = reason;
		recentevents.push_back(sample);
		++reasoncounts[reason];

		while (!recentevents.empty())
		{
			const time_t cutoff = ServerInstance->Time() - static_cast<time_t>(statseventwindow);
			if (recentevents.front().ts >= cutoff && recentevents.size() <= statseventmax)
				break;
			recentevents.pop_front();
		}
	}

	void ApplyPreset(unsigned int level, bool announce)
	{
		if (level >= std::size(presets))
			level = static_cast<unsigned int>(std::size(presets) - 1);

		const Preset& preset = presets[level];
		const LevelSettings& settings = levelsettings[level];
		action = settings.action;
		kmersize = settings.kmersize;
		minlength = settings.minlength;
		earlymaxmessages = settings.earlymaxmessages;
		earlyratio = settings.earlyratio;
		earlyweight = settings.earlyweight;
		spammythreshold = settings.spammythreshold;
		maxcachesize = settings.maxcachesize;
		cachettl = settings.cachettl;
		reputationttl = settings.reputationttl;
		warmupobservations = settings.warmupobservations;
		tarpitdelay = settings.tarpitdelay;
		tarpitmultiplier = settings.tarpitmultiplier;
		tarpitmaxdelay = settings.tarpitmaxdelay;
		fanoutdelay = settings.fanoutdelay;
		fanoutmultiplier = settings.fanoutmultiplier;
		fanoutwindow = settings.fanoutwindow;
		kmerpenalty = settings.kmerpenalty;
		kmerpenaltycap = settings.kmerpenaltycap;
		kmerpenaltyminratio = settings.kmerpenaltyminratio;
		kmerpenaltyminscore = settings.kmerpenaltyminscore;
		glineduration = settings.glineduration;
		exemptmodes = settings.exemptmodes;
		trustedmodes = settings.trustedmodes;
		interactionlowweight = settings.interactionlowweight;
		interactionspammyweight = settings.interactionspammyweight;
		interactionpenaltyweight = settings.interactionpenaltyweight;
		interactionminsignals = settings.interactionminsignals;
		interactionexponent = settings.interactionexponent;
		trustdecay = settings.trustdecay;
		trustweight = settings.trustweight;
		feedbackpositive = settings.feedbackpositive;
		feedbacknegative = settings.feedbacknegative;
		currentlevel = level;

		if (announce)
			ServerInstance->SNO.WriteGlobalSno('a', "m_tarpit: applied preset {} ({}).", level, preset.name);
	}

	void ResetLevelSettings()
	{
		for (unsigned int i = 0; i < levelsettings.size(); ++i)
			levelsettings[i] = BuildDefaultSettings(i);
	}

	LevelSettings BuildDefaultSettings(unsigned int level) const
	{
		LevelSettings settings;
		const Preset& preset = presets[level];
		settings.tarpitdelay = preset.delay;
		settings.tarpitmultiplier = preset.multiplier;
		settings.tarpitmaxdelay = preset.maxdelay;
		settings.spammythreshold = preset.spammy_threshold;
		settings.earlyratio = preset.early_ratio;
		settings.earlyweight = preset.early_weight;
		settings.fanoutwindow = preset.fanout_window;
		settings.fanoutdelay = preset.fanout_delay;
		settings.fanoutmultiplier = preset.fanout_multiplier;
		settings.kmerpenalty = preset.kmer_penalty;
		settings.kmerpenaltycap = preset.kmer_penalty_cap;
		settings.kmerpenaltyminratio = preset.kmer_penalty_min_ratio;
		settings.kmerpenaltyminscore = preset.kmer_penalty_min_score;
		settings.reputationttl = preset.reputation_ttl;
		settings.interactionlowweight = preset.interaction_low_weight;
		settings.interactionspammyweight = preset.interaction_spammy_weight;
		settings.interactionpenaltyweight = preset.interaction_penalty_weight;
		settings.interactionminsignals = preset.interaction_min_signals;
		settings.interactionexponent = preset.interaction_exponent;
		settings.trustdecay = preset.trust_decay;
		settings.trustweight = preset.trust_weight;
		settings.feedbackpositive = feedbackpositive;
		settings.feedbacknegative = feedbacknegative;
		return settings;
	}

	static std::string ActionToString(SpamAction action)
	{
		switch (action)
		{
			case SpamAction::BLOCK:
				return "block";
			case SpamAction::GLINE:
				return "gline";
			case SpamAction::SILENT:
				return "silent";
			case SpamAction::DELAY:
			default:
				return "delay";
		}
	}

	static SpamAction ParseAction(const std::string& name)
	{
		std::string lower = name;
		std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
		if (lower == "gline")
			return SpamAction::GLINE;
		if (lower == "block")
			return SpamAction::BLOCK;
		if (lower == "silent")
			return SpamAction::SILENT;
		return SpamAction::DELAY;
	}

	void OverrideSettings(LevelSettings& settings, const std::shared_ptr<ConfigTag>& tag)
	{
		settings.kmersize = std::clamp(tag->getNum<size_t>("k", settings.kmersize), static_cast<size_t>(3), static_cast<size_t>(6));
		settings.minlength = tag->getNum<size_t>("minlength", settings.minlength, 6, 200);
		settings.earlymaxmessages = tag->getNum<size_t>("early_max_messages", settings.earlymaxmessages, 1, 50);
		settings.earlyratio = tag->getNum<double>("early_ratio", settings.earlyratio, 0.0, 1.0);
		settings.earlyweight = tag->getNum<double>("early_weight", settings.earlyweight, 0.0, 30.0);
		settings.spammythreshold = tag->getNum<double>("spammy_threshold", settings.spammythreshold, 0.0, 1.0);
		settings.maxcachesize = tag->getNum<size_t>("max_cache_size", settings.maxcachesize, 1000, 500000);
		settings.cachettl = tag->getDuration("cache_ttl", settings.cachettl, 60, 7200);
		settings.reputationttl = tag->getDuration("reputation_ttl", settings.reputationttl, 60, 7200);
		settings.warmupobservations = tag->getNum<size_t>("warmup_observations", settings.warmupobservations, 0, 1000000);
		settings.tarpitdelay = tag->getNum<double>("tarpit_delay", settings.tarpitdelay, 1.0, 600.0);
		settings.tarpitmultiplier = tag->getNum<double>("tarpit_multiplier", settings.tarpitmultiplier, 1.0, 10.0);
		settings.tarpitmaxdelay = tag->getDuration("tarpit_max_delay", settings.tarpitmaxdelay, 0, 86400);
		settings.fanoutdelay = tag->getNum<double>("fanout_delay", settings.fanoutdelay, 0.0, 60.0);
		settings.fanoutmultiplier = tag->getNum<double>("fanout_multiplier", settings.fanoutmultiplier, 1.0, 10.0);
		settings.fanoutwindow = tag->getDuration("fanout_window", settings.fanoutwindow, 0, 600);
		settings.kmerpenalty = tag->getNum<double>("kmer_penalty", settings.kmerpenalty, 0.0, 3600.0);
		settings.kmerpenaltycap = tag->getDuration("kmer_penalty_cap", settings.kmerpenaltycap, 0, 86400);
		settings.kmerpenaltyminratio = tag->getNum<double>("kmer_penalty_min_ratio", settings.kmerpenaltyminratio, 0.0, 1.0);
		settings.kmerpenaltyminscore = tag->getNum<double>("kmer_penalty_min_score", settings.kmerpenaltyminscore, 0.0, 1000.0);
		settings.glineduration = tag->getDuration("gline_duration", settings.glineduration, 60, 86400);
		settings.exemptmodes = tag->getString("exemptmodes", settings.exemptmodes);
		settings.trustedmodes = tag->getString("trustedmodes", settings.trustedmodes);
		settings.interactionlowweight = tag->getNum<double>("interaction_low_weight", settings.interactionlowweight, 0.0, 10.0);
		settings.interactionspammyweight = tag->getNum<double>("interaction_spammy_weight", settings.interactionspammyweight, 0.0, 10.0);
		settings.interactionpenaltyweight = tag->getNum<double>("interaction_penalty_weight", settings.interactionpenaltyweight, 0.0, 10.0);
		settings.interactionminsignals = tag->getNum<unsigned int>("interaction_min_signals", settings.interactionminsignals, 1, 3);
		settings.interactionexponent = tag->getNum<double>("interaction_exponent", settings.interactionexponent, 0.5, 5.0);
		settings.trustdecay = tag->getDuration("trust_decay", settings.trustdecay, 0, 7200);
		settings.trustweight = tag->getNum<double>("trust_weight", settings.trustweight, 0.0, 5.0);
		settings.feedbackpositive = tag->getNum<double>("feedback_positive", settings.feedbackpositive, 0.0, 100.0);
		settings.feedbacknegative = tag->getNum<double>("feedback_negative", settings.feedbacknegative, 0.0, 100.0);

		const std::string actionstr = tag->getString("action", ActionToString(settings.action));
		settings.action = ParseAction(actionstr);
	}

	LevelSettings& CurrentLevelSettings()
	{
		if (currentlevel >= levelsettings.size())
			currentlevel = static_cast<unsigned int>(levelsettings.size() - 1);
		return levelsettings[currentlevel];
	}

	double CalculateInteractionBoost(bool lowentropy, bool spammy, bool penalty) const
	{
		unsigned int signals = 0;
		if (lowentropy)
			++signals;
		if (spammy)
			++signals;
		if (penalty)
			++signals;
		if (signals < interactionminsignals)
			return 1.0;

		double product = 1.0;
		if (lowentropy && interactionlowweight > 0.0)
			product *= (1.0 + interactionlowweight);
		if (spammy && interactionspammyweight > 0.0)
			product *= (1.0 + interactionspammyweight);
		if (penalty && interactionpenaltyweight > 0.0)
			product *= (1.0 + interactionpenaltyweight);

		if (product <= 0.0 || interactionexponent <= 0.0)
			return 1.0;
		double boost = std::pow(product, interactionexponent);
		if (!std::isfinite(boost) || boost < 1.0)
			return 1.0;
		return boost;
	}

	double CalculateTrustBoost(const UserStats& stats, time_t now) const
	{
		if (!trustweight || !trustdecay || !stats.connected)
			return 1.0;
		double age = static_cast<double>(now - stats.connected);
		if (age <= 0.0)
			age = 0.0;
		if (age >= static_cast<double>(trustdecay))
			return 1.0;
		double factor = 1.0 + trustweight * (1.0 - (age / static_cast<double>(trustdecay)));
		return (factor < 1.0 ? 1.0 : factor);
	}

	bool ParseUnsigned(const std::string& text, unsigned long& out) const
	{
		if (text.empty())
			return false;
		char* end = nullptr;
		errno = 0;
		unsigned long val = std::strtoul(text.c_str(), &end, 10);
		if ((end == nullptr) || (*end != '\0') || errno == ERANGE)
			return false;
		out = val;
		return true;
	}

	template <typename T>
	void SetNumeric(User* user, T& field, const std::string& value, double min, double max, const std::string& name)
	{
		T converted = ConvToNum<T>(value);
		const double dbl = static_cast<double>(converted);
		if (dbl < min || dbl > max)
			throw ModuleException(this, INSP_FORMAT("{} out of range", name));
		field = converted;
	}

	UserStats* GetStats(LocalUser* user)
	{
		auto* stats = userstats.Get(user);
		if (!stats)
		{
			stats = new UserStats;
			stats->connected = user->signon;
			userstats.Set(user, stats);
		}
		return stats;
	}

	void UpdateEarlyStats(UserStats& stats, const std::vector<std::string>& kmers, double msgweight) const
	{
		if (stats.early_messages >= earlymaxmessages)
			return;

		stats.early_messages++;
		stats.early_totalkmers += kmers.size();
		stats.early_weight_sum += msgweight * kmers.size();
		for (const auto& kmer : kmers)
			stats.early_distinct.insert(kmer);
	}

	double GetEntropyRatio(const UserStats& stats) const
	{
		if (!stats.early_totalkmers)
			return 1.0;
		return static_cast<double>(stats.early_distinct.size()) / static_cast<double>(stats.early_totalkmers);
	}

	double GetWeightAverage(const UserStats& stats, double msgweight) const
	{
		if (!stats.early_totalkmers)
			return msgweight;
		return stats.early_weight_sum / static_cast<double>(stats.early_totalkmers);
	}

	double CalculateMessageWeight(const std::vector<std::string>& kmers) const
	{
		if (kmers.empty() || !totalobservations)
			return 0.0;

		double total = 0.0;
		for (const auto& kmer : kmers)
		{
			const auto it = cache.find(kmer);
			const double freq = (it == cache.end() ? 0.0 : static_cast<double>(it->second.frequency));
			total += std::log((static_cast<double>(totalobservations) + 1.0) / (freq + 1.0));
		}
		return total / static_cast<double>(kmers.size());
	}

	double CalculateSpammyRatio(const std::vector<std::string>& kmers, time_t now)
	{
		if (kmers.empty())
			return 0.0;

		size_t hits = 0;
		for (const auto& kmer : kmers)
		{
			auto it = reputation.find(kmer);
			if (it == reputation.end())
				continue;
			if ((now - it->second.last_seen) > static_cast<time_t>(reputationttl))
				continue;
			if (it->second.score > 0.0)
				hits++;
		}

		return static_cast<double>(hits) / static_cast<double>(kmers.size());
	}

	unsigned long CalculateFanoutPenalty(UserStats& stats, const std::string& target, time_t now)
	{
		if ((fanoutdelay <= 0.0) || !fanoutwindow)
			return 0;

		while (!stats.fanout_recent.empty() && (now - stats.fanout_recent.front().time) > static_cast<time_t>(fanoutwindow))
		{
			const FanoutHit& expired = stats.fanout_recent.front();
			auto it = stats.fanout_counts.find(expired.target);
			if (it != stats.fanout_counts.end())
			{
				if (it->second <= 1)
					stats.fanout_counts.erase(it);
				else
					it->second--;
			}
			stats.fanout_recent.pop_front();
		}

		stats.fanout_recent.push_back({target, now});
		stats.fanout_counts[target]++;

		const size_t unique = stats.fanout_counts.size();
		if (unique <= 1)
			return 0;

		double penalty = fanoutdelay;
		if (fanoutmultiplier > 1.0 && unique > 1)
			penalty *= std::pow(fanoutmultiplier, static_cast<double>(unique - 1));

		if (penalty <= 0.0)
			return 0;

		if (penalty > static_cast<double>(std::numeric_limits<unsigned long>::max()))
			return std::numeric_limits<unsigned long>::max();
		return static_cast<unsigned long>(std::ceil(penalty));
	}

	unsigned long CalculateKmerPenalty(const std::vector<std::string>& kmers, double spammy_ratio, time_t now)
	{
		if ((kmerpenalty <= 0.0) || (spammy_ratio < kmerpenaltyminratio))
			return 0;

		insp::flat_set<std::string> distinct(kmers.begin(), kmers.end());
		double scoretotal = 0.0;
		for (const auto& kmer : distinct)
		{
			auto it = reputation.find(kmer);
			if (it == reputation.end())
				continue;
			if ((now - it->second.last_seen) > static_cast<time_t>(reputationttl))
				continue;
			if (it->second.score < kmerpenaltyminscore)
				continue;
			scoretotal += it->second.score;
		}

		if (scoretotal <= 0.0)
			return 0;

		double penalty = scoretotal * kmerpenalty;
		if (kmerpenaltycap && penalty > static_cast<double>(kmerpenaltycap))
			penalty = kmerpenaltycap;

		if (penalty > static_cast<double>(std::numeric_limits<unsigned long>::max()))
			return std::numeric_limits<unsigned long>::max();
		return static_cast<unsigned long>(std::ceil(penalty));
	}

	void MarkKmersSpammy(const std::vector<std::string>& kmers, time_t now)
	{
		for (const auto& kmer : kmers)
		{
			ReputationEntry& entry = reputation[kmer];
			entry.score += 1.0;
			entry.last_seen = now;
		}
	}

	unsigned long QueueMessage(UserStats& stats, LocalUser* user, MessageTarget& target, MessageDetails& details, time_t now,
		double interactionboost, unsigned long fanoutbonus, unsigned long kmerbonus, bool& dropped)
	{
		dropped = false;

		User* dest = target.Get<User>();
		if (!dest)
			return 0;

		TarpitMessage pending;
		pending.command = (details.type == MessageType::NOTICE ? "NOTICE" : "PRIVMSG");
		pending.target = dest->nick;
		pending.message = details.text;

		double delay = tarpitdelay * interactionboost;
		if (now < stats.tarpit_until && stats.last_delay)
			delay = stats.last_delay;

		if (now < stats.tarpit_until)
			delay = std::ceil(delay * tarpitmultiplier);

		if (fanoutbonus)
		{
			const double scaled = std::ceil(static_cast<double>(delay) * tarpitmultiplier);
			if (scaled > static_cast<double>(std::numeric_limits<unsigned long>::max()))
				delay = std::numeric_limits<unsigned long>::max();
			else
				delay += fanoutbonus;
		}

		if (kmerbonus)
		{
			if (delay > std::numeric_limits<double>::max() - kmerbonus)
				delay = std::numeric_limits<double>::max();
			else
				delay += kmerbonus;
		}

		if (tarpitmaxdelay && delay >= static_cast<double>(tarpitmaxdelay))
		{
			dropped = true;
			stats.last_delay = tarpitmaxdelay;
			return tarpitmaxdelay;
		}

		if (delay < tarpitdelay)
			delay = tarpitdelay;

		unsigned long finaldelay = static_cast<unsigned long>(std::ceil(delay));
		pending.release = std::max(now, stats.tarpit_until) + finaldelay;
		stats.tarpit_until = pending.release;
		stats.last_delay = finaldelay;
		stats.queue.push_back(pending);

		if (IS_LOCAL(user))
			user->WriteNotice("Your message has been delayed by the spam filter.");

		return finaldelay;
	}

	void ProcessQueues(time_t now)
	{
		const UserManager::LocalList& locals = ServerInstance->Users.GetLocalUsers();
		for (const auto& it : locals)
		{
			LocalUser* user = it;
			auto* stats = userstats.Get(user);
			if (!stats)
				continue;

			while (!stats->queue.empty() && stats->queue.front().release <= now)
			{
				TarpitMessage msg = stats->queue.front();
				stats->queue.pop_front();

				CommandBase::Params params;
				params.push_back(msg.target);
				params.push_back(msg.message);

				stats->bypass = true;
				if (ServerInstance->Parser.CallHandler(msg.command, params, user) != CmdResult::SUCCESS)
					user->WriteNotice("A delayed message could not be delivered.");
				stats->bypass = false;
			}

			if (stats->queue.empty() && now >= stats->tarpit_until)
				stats->tarpit_until = now;
		}
	}

	void HandleDetection(LocalUser* user, MessageTarget& target, const std::string& normalized)
	{
		User* dest = target.Get<User>();
		const std::string targetname = dest ? dest->nick : "*";

		ServerInstance->Logs.Normal(MODNAME, "k-mer spam detected: {} -> {} text='{}'",
			user->GetRealHost(), targetname, normalized);

		switch (action)
		{
			case SpamAction::GLINE:
				IssueGLine(user);
				[[fallthrough]];
			case SpamAction::BLOCK:
				user->WriteNumeric(Numerics::CannotSendTo(dest, "Your message was blocked by the spam filter."));
				break;
			case SpamAction::SILENT:
				break;
			case SpamAction::DELAY:
				break;
		}
	}

	void IssueGLine(LocalUser* user)
	{
		auto* gline = new GLine(ServerInstance->Time(), glineduration, ServerInstance->Config->ServerName,
			"K-mer spam detected", user->GetBanUser(true), user->GetAddress());
		if (!ServerInstance->XLines->AddLine(gline, nullptr))
		{
			delete gline;
			return;
		}

		ServerInstance->SNO.WriteGlobalSno('x', "{} added a timed G-line on {} lasting {} for {}",
			gline->source, gline->Displayable(), Duration::ToString(glineduration), gline->reason);
		ServerInstance->XLines->ApplyLines();
	}

	void UpdateCache(const std::vector<std::string>& kmers, time_t now)
	{
		for (const auto& kmer : kmers)
		{
			KmerData& entry = cache[kmer];
			entry.frequency++;
			entry.last_seen = now;
		}

		totalobservations += kmers.size();
		EnforceCacheLimit();
	}

	void CleanupCache(time_t now)
	{
		if (now == lastcachecleanup || now - lastcachecleanup < 30)
			return;
		lastcachecleanup = now;

		for (auto it = cache.begin(); it != cache.end(); )
		{
			if ((now - it->second.last_seen) > static_cast<time_t>(cachettl))
			{
				if (totalobservations >= it->second.frequency)
					totalobservations -= it->second.frequency;
				it = cache.erase(it);
			}
			else
			{
				++it;
			}
		}
	}

	void EnforceCacheLimit()
	{
		while (cache.size() > maxcachesize)
		{
			auto oldest = cache.begin();
			for (auto it = std::next(cache.begin()); it != cache.end(); ++it)
			{
				if (it->second.last_seen < oldest->second.last_seen)
					oldest = it;
			}
			if (totalobservations >= oldest->second.frequency)
				totalobservations -= oldest->second.frequency;
			cache.erase(oldest);
		}
	}

	void CleanupReputation(time_t now)
	{
		if (now == lastreputationcleanup || now - lastreputationcleanup < 60)
			return;
		lastreputationcleanup = now;

		for (auto it = reputation.begin(); it != reputation.end(); )
		{
			if ((now - it->second.last_seen) > static_cast<time_t>(reputationttl))
				it = reputation.erase(it);
			else
				++it;
		}
	}

	static bool HasListedMode(LocalUser* user, const std::string& modes)
	{
		if (!user || modes.empty())
			return false;

		for (const unsigned char ch : modes)
		{
			if (!ch)
				continue;
			if (user->IsModeSet(ch))
				return true;
		}
		return false;
	}

	std::string NormalizeText(const std::string& input) const
	{
		std::string normalized;
		normalized.reserve(input.size());

		try
		{
			utf8::iterator<std::string::const_iterator> it(input.begin(), input.begin(), input.end());
			utf8::iterator<std::string::const_iterator> itend(input.end(), input.begin(), input.end());
			while (it != itend)
			{
				uint32_t cp = *it;
				++it;

				if (IsZeroWidth(cp))
					continue;

				if (cp == ' ' || cp == '\t' || cp == '\n' || cp == '\r')
					continue;

				if (cp >= 'A' && cp <= 'Z')
					cp += 32;

				if (!IsAllowedChar(cp))
					continue;

				utf8::append(cp, std::back_inserter(normalized));
			}
		}
		catch (const utf8::exception&)
		{
			for (unsigned char c : input)
			{
				uint32_t cp = c;
				if (IsZeroWidth(cp) || cp == ' ' || cp == '\t' || cp == '\n' || cp == '\r')
					continue;

				if (cp >= 'A' && cp <= 'Z')
					cp += 32;

				if (!IsAllowedChar(cp))
					continue;

				normalized.push_back(static_cast<char>(cp));
			}
		}

		return normalized;
	}

	std::vector<std::string> ExtractKmers(const std::string& text) const
	{
		std::vector<std::string> kmers;
		if (text.length() < kmersize)
			return kmers;

		kmers.reserve(text.length() - kmersize + 1);
		for (size_t idx = 0; idx <= text.length() - kmersize; ++idx)
			kmers.push_back(text.substr(idx, kmersize));
		return kmers;
	}

	static bool IsAllowedChar(uint32_t cp)
	{
		return (cp >= 'a' && cp <= 'z') || (cp >= '0' && cp <= '9') || cp == '.' || cp == '-' || cp == '_';
	}

	bool LearnSample(User* user, bool positive, const std::string& text)
	{
		const std::string normalized = NormalizeText(text);
		if (normalized.length() < kmersize)
		{
			user->WriteNotice("TARPIT: sample too short after normalization");
			return false;
		}

		const std::vector<std::string> kmers = ExtractKmers(normalized);
		if (kmers.empty())
		{
			user->WriteNotice("TARPIT: sample produced no k-mers");
			return false;
		}

		const time_t now = ServerInstance->Time();
		const double delta = (positive ? feedbackpositive : -feedbacknegative);
		for (const auto& kmer : kmers)
		{
			ReputationEntry& entry = reputation[kmer];
			entry.score = std::clamp(entry.score + delta, -feedbackmaxscore, feedbackmaxscore);
			entry.last_seen = now;
		}

		if (positive)
			UpdateCache(kmers, now);

		const std::string label = (positive ? "positive" : "negative");
		ServerInstance->SNO.WriteGlobalSno('a', "m_tarpit: {} submitted {} sample ({} k-mers, delta={:.2f}).",
			user->nick, label, kmers.size(), std::abs(delta));
		user->WriteNotice(INSP_FORMAT("TARPIT: recorded {} sample ({} k-mers).", label, kmers.size()));
		return true;
	}

public:
	// Interface for CommandTarpit
	friend class CommandTarpit;
};

CommandTarpit::CommandTarpit(ModuleTarpit& mod)
	: Command(&mod, "TARPIT", 1)
	, parent(mod)
{
	access_needed = CmdAccess::OPERATOR;
	syntax = { "HELP", "STATS [seconds]", "CONFIG GET [key]", "CONFIG SET <key> <value>", "LEARN <pos|neg> <text>" };
}

CmdResult CommandTarpit::Handle(User* user, const Params& params)
{
	if (!user->IsOper())
		return CmdResult::FAILURE;

	if (params.empty())
	{
		SendHelp(user);
		return CmdResult::SUCCESS;
	}

	std::string sub = params[0];
	std::transform(sub.begin(), sub.end(), sub.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	if (sub == "help")
	{
		SendHelp(user);
		return CmdResult::SUCCESS;
	}
	else if (sub == "stats")
	{
		unsigned long window = 300;
		if (params.size() > 1)
		{
			if (!parent.ParseUnsigned(params[1], window))
			{
				user->WriteNotice("TARPIT: invalid window");
				return CmdResult::FAILURE;
			}
		}
		parent.SendStats(user, window);
		return CmdResult::SUCCESS;
	}
	else if (sub == "learn")
	{
		if (params.size() < 3)
		{
			user->WriteNotice("TARPIT: LEARN <pos|neg> <text>");
			return CmdResult::FAILURE;
		}

		std::string label = params[1];
		std::transform(label.begin(), label.end(), label.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
		bool positive = false;
		if (label == "pos" || label == "positive" || label == "spam")
			positive = true;
		else if (label == "neg" || label == "negative" || label == "ham")
			positive = false;
		else
		{
			user->WriteNotice("TARPIT: LEARN <pos|neg> <text>");
			return CmdResult::FAILURE;
		}

		std::string sample = params[2];
		for (size_t idx = 3; idx < params.size(); ++idx)
		{
			sample.push_back(' ');
			sample.append(params[idx]);
		}

		if (parent.LearnSample(user, positive, sample))
			return CmdResult::SUCCESS;
		return CmdResult::FAILURE;
	}

	if (sub == "config")
	{
		if (params.size() < 2)
		{
			user->WriteNotice("TARPIT: CONFIG GET [key] | CONFIG SET <key> <value>");
			return CmdResult::FAILURE;
		}

		std::string action = params[1];
		std::transform(action.begin(), action.end(), action.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
		if (action == "get")
		{
			const std::string key = (params.size() > 2 ? params[2] : "");
			parent.SendConfig(user, key);
			return CmdResult::SUCCESS;
		}
		else if (action == "set")
		{
			if (params.size() < 4)
			{
				user->WriteNotice("TARPIT: CONFIG SET <key> <value>");
				return CmdResult::FAILURE;
			}

			if (parent.SetConfig(user, params[2], params[3]))
				return CmdResult::SUCCESS;
			return CmdResult::FAILURE;
		}

		user->WriteNotice("TARPIT: unknown CONFIG action");
		return CmdResult::FAILURE;
	}

	user->WriteNotice("TARPIT: unknown subcommand");
	return CmdResult::FAILURE;
}

void CommandTarpit::SendHelp(User* user)
{
	user->WriteNotice("TARPIT: HELP | STATS [seconds] | CONFIG GET [key] | CONFIG SET <key> <value> | LEARN <pos|neg> <text>");
	user->WriteNotice("HELP: /TARPIT stats [seconds] shows recent hit rate; \x02config\x02 adjusts runtime knobs; \x02learn\x02 feeds labeled samples.");
}

MODULE_INIT(ModuleTarpit)
