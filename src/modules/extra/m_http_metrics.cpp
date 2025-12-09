/*
 * InspIRCd -- Internet Relay Chat Daemon
 * RelayOS custom module: Prometheus-friendly metrics over httpd.
 *
 * Exposes gauges/counters on /metrics:
 * - inspircd_users_current{scope="global|local"}
 * - inspircd_channels_current
 * - inspircd_opers_current
 * - inspircd_uptime_seconds
 * - inspircd_connects_total
 * - inspircd_disconnects_total
 * - inspircd_messages_total{type="privmsg|notice",target="channel|user|server"}
 * - inspircd_channel_messages_total{channel="<name>"} (can be disabled)
 * - inspircd_command_use_total{name="<command>"} (since boot)
 * - inspircd_tarpit_* (if m_tarpit is loaded)
 * - inspircd_user_modes_total{mode="<char>",direction="add|del"}
 * - inspircd_metadata_total{key="<key>",action="set|unset"}; value breakdown for configured keys
 *
 * Configuration (<httpmetrics>):
 *   path             - HTTP path (default /metrics)
 *   tarpit_window    - Window for tarpit window_* metrics (default 300s)
 *   channel_metrics  - bool, include per-channel message counters (default yes)
 *   metadata_value_keys - comma-separated keys to break down by value (default empty = none)
 *
 * Optional tarpit metrics require m_tarpit providing the tarpit_metrics service.
 */

#include "inspircd.h"
#include "modules/httpd.h"
#include "message.h"
#include "modules.h"
#include "modules/extra/tarpit_metrics.h"
#include "modules/ircv3_metadata.h"
#include "modechange.h"

#include <initializer_list>
#include <map>
#include <set>
#include <sstream>

namespace
{
	std::string EscapeLabel(const std::string& in)
	{
		std::string out;
		out.reserve(in.size());
		for (char c : in)
		{
			switch (c)
			{
				case '\\':
				case '"':
				case '\n':
					out.push_back('\\');
					break;
				default:
					break;
			}
			out.push_back(c);
		}
		return out;
	}
}

class ModuleHttpMetrics final
	: public Module
	, public HTTPRequestEventListener
	, public IRCv3::Metadata::EventListener
{
private:
	HTTPdAPI api;
	dynamic_reference<TarpitMetricsProvider> tarpit;

	std::string path = "/metrics";
	unsigned long tarpit_window = 300;
	bool channel_metrics = true;
	std::set<std::string> metadata_value_keys;

	uint64_t connects_total = 0;
	uint64_t disconnects_total = 0;
	uint64_t messages_privmsg_channel = 0;
	uint64_t messages_privmsg_user = 0;
	uint64_t messages_privmsg_server = 0;
	uint64_t messages_notice_channel = 0;
	uint64_t messages_notice_user = 0;
	uint64_t messages_notice_server = 0;

	std::map<std::string, uint64_t> channel_message_counts;
	std::map<std::pair<std::string, std::string>, uint64_t> user_mode_counts; // key: (modechar, direction)
	std::map<std::pair<std::string, std::string>, uint64_t> metadata_key_counts; // key: (key, action)
	std::map<std::pair<std::string, std::string>, uint64_t> metadata_value_counts; // key: (key, value)

public:
	ModuleHttpMetrics()
		: Module(VF_VENDOR, "Expose Prometheus-style metrics over the InspIRCd httpd module.")
		, HTTPRequestEventListener(this)
		, api(this)
		, IRCv3::Metadata::EventListener(this)
		, tarpit(this, "tarpit_metrics")
	{
	}

	void ReadConfig(ConfigStatus&) override
	{
		const auto& tag = ServerInstance->Config->ConfValue("httpmetrics");
		path = tag->getString("path", "/metrics", 1, ServerInstance->Config->Limits.MaxLine - 1);
		tarpit_window = tag->getDuration("tarpit_window", 300, 0, 86400);
		channel_metrics = tag->getBool("channel_metrics", true);

		metadata_value_keys.clear();
		const std::string rawkeys = tag->getString("metadata_value_keys");
		std::stringstream ss(rawkeys);
		std::string item;
		while (std::getline(ss, item, ','))
		{
			insp::trim(item);
			if (!item.empty())
				metadata_value_keys.insert(item);
		}
	}

	void OnUserConnect(LocalUser*) override
	{
		++connects_total;
	}

	void OnUserDisconnect(LocalUser*) override
	{
		++disconnects_total;
	}

	void OnUserPostMessage(User*, const MessageTarget& target, const MessageDetails& details) override
	{
		if (details.type == MessageType::PRIVMSG)
		{
			switch (target.type)
			{
				case MessageTarget::TYPE_CHANNEL:
					++messages_privmsg_channel;
					if (channel_metrics && target.Get<Channel>())
						++channel_message_counts[target.Get<Channel>()->name];
					break;
				case MessageTarget::TYPE_USER:
					++messages_privmsg_user;
					break;
				case MessageTarget::TYPE_SERVER:
					++messages_privmsg_server;
					break;
			}
		}
		else if (details.type == MessageType::NOTICE)
		{
			switch (target.type)
			{
				case MessageTarget::TYPE_CHANNEL:
					++messages_notice_channel;
					if (channel_metrics && target.Get<Channel>())
						++channel_message_counts[target.Get<Channel>()->name];
					break;
				case MessageTarget::TYPE_USER:
					++messages_notice_user;
					break;
			case MessageTarget::TYPE_SERVER:
				++messages_notice_server;
				break;
			}
		}
	}

	void OnMode(User* user, User* usertarget, Channel* chantarget, const Modes::ChangeList& changelist, ModeParser::ModeProcessFlag) override
	{
		(void)user;
		if (!usertarget)
			return;

		for (const auto& change : changelist.getlist())
		{
			ModeHandler* mh = change.mh;
			if (!mh)
				continue;
			const char mc = mh->GetModeChar();
			if (!mc)
				continue;

			const std::string direction = change.adding ? "add" : "del";
			user_mode_counts[{std::string(1, mc), direction}]++;
		}
	}

	void OnMetadataChanged(User*, const IRCv3::Metadata::TargetInfo& target, const std::string& key, const std::string& value, bool removing) override
	{
		// Only user-level metadata for now.
		if (target.ischannel)
			return;

		const std::string action = removing ? "unset" : "set";
		metadata_key_counts[{key, action}]++;

		if (!removing)
		{
			if (metadata_value_keys.empty() || metadata_value_keys.count(key))
				metadata_value_counts[{key, value}]++;
		}
	}

	ModResult OnHTTPRequest(HTTPRequest& request) override
	{
		if (request.GetPath() != path)
			return MOD_RES_PASSTHRU;

		std::string body = BuildMetrics();
		HTTPDocumentResponse response(this, request, body);
		response.headers.SetHeader("Content-Type", "text/plain; version=0.0.4");
		api->SendResponse(response);
		return MOD_RES_DENY;
	}

private:
	std::string BuildMetrics()
	{
		std::string out;
		out.reserve(4096);

		const auto users_total = ServerInstance->Users.GetUsers().size();
		const auto users_local = ServerInstance->Users.GetLocalUsers().size();
		const auto channels = ServerInstance->Channels.GetChans().size();
		const auto opers = ServerInstance->Users.all_opers.size();
		const time_t now = ServerInstance->Time();
		const time_t uptime = now - ServerInstance->startup_time;

		EmitHelp(out, "inspircd_users_current", "Current connected users");
		EmitType(out, "inspircd_users_current", "gauge");
		EmitGauge(out, "inspircd_users_current", users_total, {{"scope", "global"}});
		EmitGauge(out, "inspircd_users_current", users_local, {{"scope", "local"}});

		EmitGaugeWithMeta(out, "inspircd_channels_current", channels, "Current channels");
		EmitGaugeWithMeta(out, "inspircd_opers_current", opers, "Current operators");
		EmitGaugeWithMeta(out, "inspircd_uptime_seconds", uptime, "Server uptime in seconds");

		EmitCounterWithMeta(out, "inspircd_connects_total", connects_total, "Total client connects since boot");
		EmitCounterWithMeta(out, "inspircd_disconnects_total", disconnects_total, "Total client disconnects since boot");

		EmitHelp(out, "inspircd_messages_total", "Total messages by type/target since boot");
		EmitType(out, "inspircd_messages_total", "counter");
		EmitCounter(out, "inspircd_messages_total", messages_privmsg_channel, {{"type", "privmsg"}, {"target", "channel"}});
		EmitCounter(out, "inspircd_messages_total", messages_privmsg_user, {{"type", "privmsg"}, {"target", "user"}});
		EmitCounter(out, "inspircd_messages_total", messages_privmsg_server, {{"type", "privmsg"}, {"target", "server"}});
		EmitCounter(out, "inspircd_messages_total", messages_notice_channel, {{"type", "notice"}, {"target", "channel"}});
		EmitCounter(out, "inspircd_messages_total", messages_notice_user, {{"type", "notice"}, {"target", "user"}});
		EmitCounter(out, "inspircd_messages_total", messages_notice_server, {{"type", "notice"}, {"target", "server"}});

		if (channel_metrics)
		{
			EmitHelp(out, "inspircd_channel_messages_total", "Channel message totals since boot");
			EmitType(out, "inspircd_channel_messages_total", "counter");
			for (const auto& [chan, count] : channel_message_counts)
			{
				EmitCounter(out, "inspircd_channel_messages_total", count, {{"channel", chan}});
			}
		}

		EmitHelp(out, "inspircd_command_use_total", "Command use counters since boot");
		EmitType(out, "inspircd_command_use_total", "counter");
		for (const auto& [cmdname, cmd] : ServerInstance->Parser.GetCommands())
		{
			EmitCounter(out, "inspircd_command_use_total", cmd->use_count, {{"name", cmdname}});
		}

		EmitHelp(out, "inspircd_user_modes_total", "User mode changes since boot");
		EmitType(out, "inspircd_user_modes_total", "counter");
		for (const auto& [key, count] : user_mode_counts)
		{
			EmitCounter(out, "inspircd_user_modes_total", count, {{"mode", key.first}, {"direction", key.second}});
		}

		if (!metadata_key_counts.empty())
		{
			EmitHelp(out, "inspircd_metadata_total", "Metadata changes (user targets)");
			EmitType(out, "inspircd_metadata_total", "counter");
			for (const auto& [key, count] : metadata_key_counts)
			{
				EmitCounter(out, "inspircd_metadata_total", count, {{"key", key.first}, {"action", key.second}});
			}
		}

		if (!metadata_value_counts.empty())
		{
			EmitHelp(out, "inspircd_metadata_value_total", "Metadata set events by key/value (user targets)");
			EmitType(out, "inspircd_metadata_value_total", "counter");
			for (const auto& [key, count] : metadata_value_counts)
			{
				EmitCounter(out, "inspircd_metadata_value_total", count, {{"key", key.first}, {"value", key.second}});
			}
		}

		if (tarpit)
		{
			TarpitMetrics metrics;
			if (tarpit->GetStats(metrics, tarpit_window))
			{
				EmitHelp(out, "inspircd_tarpit_messages_total", "Tarpit decisions since boot");
				EmitType(out, "inspircd_tarpit_messages_total", "counter");
				EmitCounter(out, "inspircd_tarpit_messages_total", metrics.total_processed, {{"outcome", "processed"}});
				EmitCounter(out, "inspircd_tarpit_messages_total", metrics.total_delayed, {{"outcome", "delayed"}});
				EmitCounter(out, "inspircd_tarpit_messages_total", metrics.total_dropped, {{"outcome", "dropped"}});

				EmitHelp(out, "inspircd_tarpit_delay_seconds_total", "Sum of tarpit delay seconds since boot");
				EmitType(out, "inspircd_tarpit_delay_seconds_total", "counter");
				EmitCounter(out, "inspircd_tarpit_delay_seconds_total", metrics.total_delay, {});

				EmitHelp(out, "inspircd_tarpit_window_messages_total", "Tarpit decisions within the configured window");
				EmitType(out, "inspircd_tarpit_window_messages_total", "counter");
				std::string windowstr = ConvToStr(tarpit_window);
				EmitCounter(out, "inspircd_tarpit_window_messages_total", metrics.window_processed, {{"outcome", "processed"}, {"window_seconds", windowstr}});
				EmitCounter(out, "inspircd_tarpit_window_messages_total", metrics.window_delayed, {{"outcome", "delayed"}, {"window_seconds", windowstr}});
				EmitCounter(out, "inspircd_tarpit_window_messages_total", metrics.window_dropped, {{"outcome", "dropped"}, {"window_seconds", windowstr}});

				EmitHelp(out, "inspircd_tarpit_window_delay_seconds_total", "Sum of tarpit delay seconds within the configured window");
				EmitType(out, "inspircd_tarpit_window_delay_seconds_total", "counter");
				EmitCounter(out, "inspircd_tarpit_window_delay_seconds_total", metrics.window_delay, {{"window_seconds", windowstr}});

				EmitGaugeWithMeta(out, "inspircd_tarpit_level", metrics.current_level, "Current tarpit level");
			}
		}

		return out;
	}

	void EmitHelp(std::string& out, const char* name, const char* help)
	{
		out.append("# HELP ");
		out.append(name);
		out.push_back(' ');
		out.append(help);
		out.push_back('\n');
	}

	void EmitType(std::string& out, const char* name, const char* type)
	{
		out.append("# TYPE ");
		out.append(name);
		out.push_back(' ');
		out.append(type);
		out.push_back('\n');
	}

	using LabelList = std::initializer_list<std::pair<std::string, std::string>>;

	void EmitGauge(std::string& out, const char* name, long long value, const LabelList& labels)
	{
		EmitMetricLine(out, name, value, labels);
	}

	void EmitGaugeWithMeta(std::string& out, const char* name, long long value, const char* help)
	{
		EmitHelp(out, name, help);
		EmitType(out, name, "gauge");
		EmitGauge(out, name, value, {});
	}

	void EmitCounter(std::string& out, const char* name, long long value, const LabelList& labels)
	{
		EmitMetricLine(out, name, value, labels);
	}

	void EmitCounterWithMeta(std::string& out, const char* name, long long value, const char* help)
	{
		EmitHelp(out, name, help);
		EmitType(out, name, "counter");
		EmitCounter(out, name, value, {});
	}

	void EmitMetricLine(std::string& out, const char* name, long long value, const LabelList& labels)
	{
		out.append(name);
		if (!labels.size())
		{
			out.push_back(' ');
			out.append(ConvToStr(value));
			out.push_back('\n');
			return;
		}

		out.push_back('{');
		bool first = true;
		for (const auto& kv : labels)
		{
			if (!first)
				out.push_back(',');
			first = false;
			out.append(kv.first);
			out.push_back('=');
			out.push_back('"');
			out.append(EscapeLabel(kv.second));
			out.push_back('"');
		}
		out.push_back('}');
		out.push_back(' ');
		out.append(ConvToStr(value));
		out.push_back('\n');
	}
};

MODULE_INIT(ModuleHttpMetrics)
