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
#include "modules/cap.h"
#include "clientprotocolmsg.h"
#include "event.h"
#include "modules/ircv3.h"
#include "modules/ircv3_batch.h"
#include "modules/ircv3_metadata.h"
#include "modules/ircv3_replies.h"
#include "modules/monitor.h"
#include "modules/server.h"

enum
{
	RPL_WHOISKEYVALUE     = 760,
	RPL_KEYVALUE          = 761,
	RPL_KEYNOTSET         = 766,
	RPL_METADATASUBOK     = 770,
	RPL_METADATAUNSUBOK   = 771,
	RPL_METADATASUBS      = 772,
	RPL_METADATASYNCLATER = 774
};

namespace IRCv3
{
	namespace Metadata
	{
		struct Entry;
		struct KeyDefinition;
		struct Target;
		class KeyMapExt;
		class Store;
		class SubscriptionStore;
		struct Settings;
	}
}

struct IRCv3::Metadata::Entry
{
	std::string value;
	std::string visibility;
	time_t updated = 0;

	Entry(const std::string& Value = std::string(), const std::string& Visibility = "*")
		: value(Value)
		, visibility(Visibility.empty() ? "*" : Visibility)
		, updated(ServerInstance->Time())
	{
	}
};

typedef insp::flat_map<std::string, IRCv3::Metadata::Entry> MetadataKeyMap;

static bool IsValidMetadataKey(const std::string& key)
{
	if (key.empty())
		return false;

	for (std::string::const_iterator it = key.begin(); it != key.end(); ++it)
	{
		const unsigned char c = static_cast<unsigned char>(*it);
		if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '/' || c == '-')
			continue;
		return false;
	}
	return true;
}

struct IRCv3::Metadata::KeyDefinition
{
	std::string name;
	unsigned int targets = IRCv3::Metadata::TARGET_ALL;
	std::string visibility = "*";
	bool operonly = false;
	bool servicesonly = false;
	std::string setpriv;
	std::string viewpriv;

	bool AllowsTarget(bool ischan) const
	{
		return (ischan ? (targets & IRCv3::Metadata::TARGET_CHANNEL) : (targets & IRCv3::Metadata::TARGET_USER));
	}
};

struct IRCv3::Metadata::Target
	: IRCv3::Metadata::TargetInfo
{
	MetadataKeyMap* GetMap(IRCv3::Metadata::Store& store, bool create) const;
	const MetadataKeyMap* PeekMap(const IRCv3::Metadata::Store& store) const;
};

/** Holds the tunable limits that we expose via the draft/metadata-2 cap. */
struct IRCv3::Metadata::Settings
{
	bool beforeconnect = false;
	unsigned int maxsubs = 32;
	unsigned int maxkeys = 32;
	unsigned int maxvaluebytes = 4096;
	bool allowunknownkeys = true;
	unsigned int defaulttargets = IRCv3::Metadata::TARGET_ALL;
	bool defaultoperonly = false;
	std::string defaultvisibility = "*";
	std::string defaultsetpriv;
	std::string defaultviewpriv;
	bool defaultservicesonly = false;
	unsigned int ratelimitrequests = 0;
	unsigned int ratelimitwindow = 0;
	unsigned int autosyncthreshold = 0;
	unsigned int syncretry = 30;
	insp::flat_map<std::string, KeyDefinition> keydefs;
	insp::flat_map<std::string, KeyDefinition> configdefs;
	struct DynamicKey
	{
		KeyDefinition def;
		Module* owner = NULL;
	};
	insp::flat_map<std::string, DynamicKey> moduledefs;
	std::string captokens;

	void ReadGeneral(ConfigTag* tag)
	{
		beforeconnect = tag->getBool("beforeconnect");
		maxsubs = tag->getNum<unsigned int>("maxsubs", 32, 1);
		maxkeys = tag->getNum<unsigned int>("maxkeys", 32, 1);
		maxvaluebytes = tag->getNum<unsigned int>("maxvaluebytes", 4096, 1);
		allowunknownkeys = tag->getBool("allowunknownkeys", true);
		defaultvisibility = tag->getString("defaultvisibility", "*", 1);
		defaultoperonly = tag->getBool("defaultoperonly");
		defaultservicesonly = tag->getBool("defaultservicesonly");
		defaultsetpriv = tag->getString("defaultsetpriv");
		defaultviewpriv = tag->getString("defaultviewpriv");
		ratelimitrequests = tag->getNum<unsigned int>("ratelimitrequests", 0);
		ratelimitwindow = tag->getNum<unsigned int>("ratelimitwindow", 0);
		autosyncthreshold = tag->getNum<unsigned int>("autosyncthreshold", 0);
		syncretry = tag->getNum<unsigned int>("syncretry", 30);
		const std::string scope = tag->getString("defaultscope");
		if (scope.empty())
			defaulttargets = IRCv3::Metadata::TARGET_ALL;
		else
			defaulttargets = ParseScope(scope, IRCv3::Metadata::TARGET_ALL);
		RebuildCapValue();
	}

	void ReadKeys(Module* mod, const ServerConfig::TagList& tags)
	{
		configdefs.clear();

		for (const auto& [_, tagptr] : tags)
		{
			ConfigTag* tag = tagptr.get();
			const std::string name = tag->getString("name");
			if (name.empty())
				throw ModuleException(mod, "<ircv3metadatakey:name> is required");

			KeyDefinition def;
			def.name = name;
			def.visibility = tag->getString("visibility", defaultvisibility.empty() ? "*" : defaultvisibility);
			def.operonly = tag->getBool("operonly", defaultoperonly);

			const std::string scope = tag->getString("scope");
			def.targets = scope.empty() ? defaulttargets : ParseScope(scope, defaulttargets);
			if (def.targets == IRCv3::Metadata::TARGET_NONE)
				throw ModuleException(mod, INSP_FORMAT("Invalid scope '{}' for key '{}'", scope, name));

			def.setpriv = tag->getString("setpriv", defaultsetpriv);
			def.viewpriv = tag->getString("viewpriv", defaultviewpriv);
			def.servicesonly = tag->getBool("servicesonly", defaultservicesonly);

			configdefs[name] = def;
		}

		RebuildKeyDefs();
	}

	const std::string* GetCapValue() const
	{
		return captokens.empty() ? NULL : &captokens;
	}

	const KeyDefinition* FindDefinition(const std::string& key) const
	{
		insp::flat_map<std::string, KeyDefinition>::const_iterator it = keydefs.find(key);
		if (it != keydefs.end())
			return &it->second;
		return NULL;
	}

	void RebuildKeyDefs()
	{
		keydefs = configdefs;
		for (insp::flat_map<std::string, DynamicKey>::const_iterator it = moduledefs.begin(); it != moduledefs.end(); ++it)
			keydefs[it->first] = it->second.def;
	}

	bool RegisterDynamicKey(Module* owner, const IRCv3::Metadata::KeySpec& spec)
	{
		if (!owner || !IsValidMetadataKey(spec.name))
			return false;

		KeyDefinition def;
		def.name = spec.name;
		def.visibility = spec.visibility.empty() ? (defaultvisibility.empty() ? "*" : defaultvisibility) : spec.visibility;
		def.operonly = spec.operonly;
		def.servicesonly = spec.servicesonly;
		def.setpriv = spec.setpriv.empty() ? defaultsetpriv : spec.setpriv;
		def.viewpriv = spec.viewpriv.empty() ? defaultviewpriv : spec.viewpriv;

		unsigned int mask = spec.targets ? (spec.targets & IRCv3::Metadata::TARGET_ALL) : 0;
		if (!mask)
			mask = defaulttargets;
		def.targets = mask;

		DynamicKey dyn;
		dyn.def = def;
		dyn.owner = owner;
		moduledefs[spec.name] = dyn;
		RebuildKeyDefs();
		return true;
	}

	void RemoveKeysOwnedBy(Module* owner)
	{
		if (!owner || moduledefs.empty())
			return;

		for (insp::flat_map<std::string, DynamicKey>::iterator it = moduledefs.begin(); it != moduledefs.end(); )
		{
			if (it->second.owner == owner)
				it = moduledefs.erase(it);
			else
				++it;
		}
		RebuildKeyDefs();
	}

 private:
	unsigned int ParseScope(const std::string& scope, unsigned int fallback) const
	{
		unsigned int mask = 0;
		irc::commasepstream ss(scope);
		for (std::string token; ss.GetToken(token); )
		{
			std::transform(token.begin(), token.end(), token.begin(), ::tolower);
			if (token == "user")
				mask |= IRCv3::Metadata::TARGET_USER;
			else if (token == "channel")
				mask |= IRCv3::Metadata::TARGET_CHANNEL;
			else if (token == "both" || token == "*")
				mask |= IRCv3::Metadata::TARGET_ALL;
		}
		return mask ? mask : fallback;
	}

	void AddToken(std::vector<std::string>& tokens, const std::string& token)
	{
		tokens.push_back(token);
	}

	void RebuildCapValue()
	{
		std::vector<std::string> tokens;
		if (beforeconnect)
			AddToken(tokens, "before-connect");

		AddToken(tokens, INSP_FORMAT("max-subs={}", maxsubs));
		AddToken(tokens, INSP_FORMAT("max-keys={}", maxkeys));
		AddToken(tokens, INSP_FORMAT("max-value-bytes={}", maxvaluebytes));

		captokens.clear();
		for (std::vector<std::string>::const_iterator it = tokens.begin(); it != tokens.end(); ++it)
		{
			if (!captokens.empty())
				captokens.push_back(',');
			captokens.append(*it);
		}
	}
};

class IRCv3::Metadata::KeyMapExt
	: public SimpleExtItem<MetadataKeyMap>
{
 public:
	KeyMapExt(Module* mod, const std::string& key, ExtensionType type)
		: SimpleExtItem<MetadataKeyMap>(mod, key, type, true)
	{
	}

	MetadataKeyMap* Get(Extensible* container, bool create)
	{
		MetadataKeyMap* map = Get(container);
		if (!map && create)
		{
			map = new MetadataKeyMap;
			Set(container, map, false);
		}
		return map;
	}

	MetadataKeyMap* Get(Extensible* container)
	{
		return SimpleExtItem<MetadataKeyMap>::Get(container);
	}
};

class IRCv3::Metadata::Store
{
	KeyMapExt usermeta;
	KeyMapExt chanmeta;

 public:
	Store(Module* mod)
		: usermeta(mod, "ircv3metadata-user", ExtensionType::USER)
		, chanmeta(mod, "ircv3metadata-chan", ExtensionType::CHANNEL)
	{
	}

	MetadataKeyMap* Get(User* user, bool create = false)
	{
		return usermeta.Get(user, create);
	}

	MetadataKeyMap* Get(Channel* chan, bool create = false)
	{
		return chanmeta.Get(chan, create);
	}

	const MetadataKeyMap* Peek(User* user) const
	{
		return const_cast<KeyMapExt&>(usermeta).Get(user);
	}

	const MetadataKeyMap* Peek(Channel* chan) const
	{
		return const_cast<KeyMapExt&>(chanmeta).Get(chan);
	}

	void Clear(User* user)
	{
		usermeta.Unset(user);
	}

	void Clear(Channel* chan)
	{
		chanmeta.Unset(chan);
	}

	void MaybeUnset(User* user)
	{
		MetadataKeyMap* map = usermeta.Get(user);
		if (map && map->empty())
			usermeta.Unset(user);
	}

	void MaybeUnset(Channel* chan)
	{
		MetadataKeyMap* map = chanmeta.Get(chan);
		if (map && map->empty())
			chanmeta.Unset(chan);
	}
};

typedef insp::flat_set<std::string> SubscriptionList;

class IRCv3::Metadata::SubscriptionStore
{
	class SubExt : public SimpleExtItem<SubscriptionList>
	{
	 public:
		SubExt(Module* mod)
			: SimpleExtItem<SubscriptionList>(mod, "ircv3metadata-subs", ExtensionType::USER, true)
		{
		}

		SubscriptionList* Get(LocalUser* user, bool create)
		{
			SubscriptionList* list = SimpleExtItem<SubscriptionList>::Get(user);
			if (!list && create)
			{
				list = new SubscriptionList;
				Set(user, list, false);
			}
			return list;
		}

		const SubscriptionList* Peek(LocalUser* user) const
		{
			return SimpleExtItem<SubscriptionList>::Get(user);
		}
	};

	SubExt ext;

 public:
	SubscriptionStore(Module* mod)
		: ext(mod)
	{
	}

	SubscriptionList* Get(LocalUser* user, bool create = false)
	{
		return ext.Get(user, create);
	}

	const SubscriptionList* Peek(LocalUser* user) const
	{
		return ext.Peek(user);
	}

	bool Has(LocalUser* user, const std::string& key) const
	{
		const SubscriptionList* list = Peek(user);
		if (!list)
			return false;
		return (list->find(key) != list->end());
	}

	void MaybeUnset(LocalUser* user)
	{
		const SubscriptionList* list = ext.Peek(user);
		if (list && list->empty())
			ext.Unset(user);
	}
};

/** Capability wrapper that surfaces the configured metadata limits. */
class MetadataCapability final : public Cap::Capability
{
	IRCv3::Metadata::Settings& settings;

 public:
	MetadataCapability(Module* mod, IRCv3::Metadata::Settings& settingsref)
		: Cap::Capability(mod, "draft/metadata-2")
		, settings(settingsref)
	{
	}

	const std::string* GetValue(LocalUser*) const override
	{
		return settings.GetCapValue();
	}
};

/** Placeholder for the upcoming METADATA command implementation. */
class CommandMetadata final : public SplitCommand
{
	IRCv3::Metadata::Settings& settings;
	IRCv3::Metadata::Store& store;
	IRCv3::Metadata::SubscriptionStore& subscriptions;
	Cap::Capability& capability;
	ClientProtocol::EventProvider& metadataevprov;
	Events::ModuleEventProvider& hookprov;
	Monitor::API& monitorapi;
	IRCv3::Replies::Fail failreply;
	IRCv3::Replies::CapReference repliescap;
	IRCv3::Batch::API batchapi;
	IRCv3::Batch::Batch subsbatch;
	IRCv3::Batch::Batch metadatabatch;
	time_t requestwindow;
	unsigned int requestlimit;
	struct RequestCounter
	{
		time_t window = 0;
		unsigned int count = 0;
	};
	insp::flat_map<LocalUser*, RequestCounter> requests;
	typedef insp::flat_map<std::string, time_t> TargetSyncMap;
	insp::flat_map<LocalUser*, TargetSyncMap> deferredsyncs;

	bool CheckSelfTarget(LocalUser* user, const std::string& target)
	{
		if ((target == "*") || irc::equals(target, user->nick))
			return true;

		failreply.SendIfCap(user, repliescap, this, "INVALID_TARGET", target, "Invalid metadata target");
		return false;
	}

	void SendFail(LocalUser* user, const std::string& code, const std::string& description)
	{
		failreply.SendIfCap(user, repliescap, this, code, description);
	}

	template<typename T1>
	void SendFail(LocalUser* user, const std::string& code, const T1& p1, const std::string& description)
	{
		failreply.SendIfCap(user, repliescap, this, code, p1, description);
	}

	template<typename T1, typename T2>
	void SendFail(LocalUser* user, const std::string& code, const T1& p1, const T2& p2, const std::string& description)
	{
		failreply.SendIfCap(user, repliescap, this, code, p1, p2, description);
	}

	template<typename T1, typename T2, typename T3>
	void SendFail(LocalUser* user, const std::string& code, const T1& p1, const T2& p2, const T3& p3, const std::string& description)
	{
		failreply.SendIfCap(user, repliescap, this, code, p1, p2, p3, description);
	}

	bool ShouldNotify(LocalUser* user, const std::string& key) const
	{
		return (capability.IsEnabled(user) && subscriptions.Has(user, key));
	}

	bool ShouldDeliver(LocalUser* user, const IRCv3::Metadata::Target& target, const std::string& key) const
	{
		if (!ShouldNotify(user, key))
			return false;
		const IRCv3::Metadata::KeyDefinition* def = settings.FindDefinition(key);
		return HasKeyViewPermission(user, target, def);
	}

	void SendKeyListNumeric(LocalUser* user, unsigned int numeric, const std::vector<std::string>& keys)
	{
		static const size_t MaxKeysPerNumeric = 10;
		for (size_t i = 0; i < keys.size(); i += MaxKeysPerNumeric)
		{
			Numeric::Numeric reply(numeric);
			const size_t end = std::min(keys.size(), i + MaxKeysPerNumeric);
			for (size_t j = i; j < end; ++j)
				reply.push(keys[j]);
			user->WriteNumeric(reply);
		}
	}

	void SendSubsChunk(LocalUser* user, const std::vector<std::string>& keys)
	{
		Numeric::Numeric numeric(RPL_METADATASUBS);
		for (std::vector<std::string>::const_iterator it = keys.begin(); it != keys.end(); ++it)
			numeric.push(*it);

		ClientProtocol::Messages::Numeric numericmsg(numeric, user);
		subsbatch.AddToBatch(numericmsg);
		user->Send(ServerInstance->GetRFCEvents().numeric, numericmsg);
	}

	time_t GetRetryDelay() const
	{
		return settings.syncretry ? settings.syncretry : 30;
	}

	void SendSyncLaterNumeric(LocalUser* user, const std::string& target, time_t delay)
	{
		Numeric::Numeric numeric(RPL_METADATASYNCLATER);
		numeric.push(target);
		if (delay > 0)
			numeric.push(ConvToStr(delay));
		user->WriteNumeric(numeric);
	}

	void ScheduleSyncLater(LocalUser* user, const std::string& target)
	{
		if (!user)
			return;

		time_t when = ServerInstance->Time() + GetRetryDelay();
		TargetSyncMap& targets = deferredsyncs[user];
		targets[target] = when;
	}

	bool CheckSyncReady(LocalUser* user, const std::string& target, time_t& wait) const
	{
		wait = 0;
		if (!user)
			return true;

		insp::flat_map<LocalUser*, TargetSyncMap>::const_iterator it = deferredsyncs.find(user);
		if (it == deferredsyncs.end())
			return true;

		const TargetSyncMap& targets = it->second;
		TargetSyncMap::const_iterator syncit = targets.find(target);
		if (syncit == targets.end())
			return true;

		const time_t now = ServerInstance->Time();
		if (syncit->second <= now)
			return true;

		wait = syncit->second - now;
		return false;
	}

	void ClearSyncSchedule(LocalUser* user, const std::string& target)
	{
		if (!user)
			return;

		insp::flat_map<LocalUser*, TargetSyncMap>::iterator it = deferredsyncs.find(user);
		if (it == deferredsyncs.end())
			return;

		TargetSyncMap& targets = it->second;
		TargetSyncMap::iterator syncit = targets.find(target);
		if (syncit != targets.end())
		{
			targets.erase(syncit);
			if (targets.empty())
				deferredsyncs.erase(it);
		}
	}

	bool MaybeDeferSync(LocalUser* user, const IRCv3::Metadata::Target& target, unsigned int entries)
	{
		if (!user || !settings.autosyncthreshold || entries == 0)
			return false;

		if (entries <= settings.autosyncthreshold)
			return false;

		ScheduleSyncLater(user, target.name);
		SendSyncLaterNumeric(user, target.name, GetRetryDelay());
		return true;
	}

	unsigned int CountChannelEntries(Channel* chan, unsigned int limit) const
	{
		if (!chan)
			return 0;

		unsigned int total = 0;
		const MetadataKeyMap* chanmap = store.Peek(chan);
		if (chanmap)
		{
			total += chanmap->size();
			if (limit && total > limit)
				return total;
		}

		const Channel::MemberMap& members = chan->GetUsers();
		for (Channel::MemberMap::const_iterator it = members.begin(); it != members.end(); ++it)
		{
			User* member = it->first;
			if (!member)
				continue;

			const MetadataKeyMap* map = store.Peek(member);
			if (!map || map->empty())
				continue;

			total += map->size();
			if (limit && total > limit)
				return total;
		}
		return total;
	}

	CmdResult HandleSub(LocalUser* user, const Params& parameters)
	{
		if (!CheckSelfTarget(user, parameters[0]))
			return CmdResult::FAILURE;

		if (parameters.size() < 3)
		{
			user->WriteNumeric(ERR_NEEDMOREPARAMS, name, "Not enough parameters");
			return CmdResult::FAILURE;
		}

		const std::string& firstkey = parameters[2];
		if (!CheckRateLimit(user, parameters[0], firstkey.empty() ? "*" : firstkey))
			return CmdResult::FAILURE;

		SubscriptionList* list = subscriptions.Get(user, true);
		std::vector<std::string> acknowledged;
		acknowledged.reserve(parameters.size() - 2);

		for (size_t i = 2; i < parameters.size(); ++i)
		{
			const std::string& key = parameters[i];
			if (!IsValidMetadataKey(key))
			{
				SendFail(user, "KEY_INVALID", key, "Invalid metadata key");
				continue;
			}

			if (!settings.allowunknownkeys && !settings.FindDefinition(key))
			{
				SendFail(user, "KEY_INVALID", key, "Unknown metadata key");
				continue;
			}

			const bool already = (list->find(key) != list->end());
			if (!already && (list->size() >= settings.maxsubs))
			{
				SendFail(user, "TOO_MANY_SUBS", key, "Too many subscriptions");
				break;
			}

			if (!already)
				list->insert(key);

			acknowledged.push_back(key);
		}

		if (acknowledged.empty())
		{
			subscriptions.MaybeUnset(user);
			return CmdResult::FAILURE;
		}

		SendKeyListNumeric(user, RPL_METADATASUBOK, acknowledged);
		SendSubscriptionSnapshot(user, acknowledged);
		return CmdResult::SUCCESS;
	}

	CmdResult HandleUnsub(LocalUser* user, const Params& parameters)
	{
		if (!CheckSelfTarget(user, parameters[0]))
			return CmdResult::FAILURE;

		if (parameters.size() < 3)
		{
			user->WriteNumeric(ERR_NEEDMOREPARAMS, name, "Not enough parameters");
			return CmdResult::FAILURE;
		}

		SubscriptionList* list = subscriptions.Get(user);
		std::vector<std::string> acknowledged;
		acknowledged.reserve(parameters.size() - 2);

		for (size_t i = 2; i < parameters.size(); ++i)
		{
			const std::string& key = parameters[i];
			if (!IsValidMetadataKey(key))
			{
				SendFail(user, "KEY_INVALID", key, "Invalid metadata key");
				continue;
			}

			if (list)
				list->erase(key);

			acknowledged.push_back(key);
		}

		if (list)
			subscriptions.MaybeUnset(user);

		if (acknowledged.empty())
			return CmdResult::FAILURE;

		SendKeyListNumeric(user, RPL_METADATAUNSUBOK, acknowledged);
		return CmdResult::SUCCESS;
	}

	CmdResult HandleSubs(LocalUser* user, const Params& parameters)
	{
		if (!CheckSelfTarget(user, parameters[0]))
			return CmdResult::FAILURE;

		if (!CheckRateLimit(user, parameters[0], "*"))
			return CmdResult::FAILURE;

		const SubscriptionList* list = subscriptions.Peek(user);
		if (batchapi)
			batchapi->Start(subsbatch);

		if (list && !list->empty())
		{
			std::vector<std::string> chunk;
			chunk.reserve(10);

			for (SubscriptionList::const_iterator it = list->begin(); it != list->end(); ++it)
			{
				chunk.push_back(*it);
				if (chunk.size() >= 10)
				{
					SendSubsChunk(user, chunk);
					chunk.clear();
				}
			}

			if (!chunk.empty())
				SendSubsChunk(user, chunk);
		}

		if (batchapi)
			batchapi->End(subsbatch);
		return CmdResult::SUCCESS;
	}

	void SendKeysForTarget(LocalUser* viewer, const IRCv3::Metadata::Target& target, const std::vector<std::string>& keys)
	{
		if (!capability.IsEnabled(viewer))
			return;

		if (!CanView(viewer, target))
			return;

		const MetadataKeyMap* map = target.PeekMap(store);
		if (!map || map->empty())
			return;

		bool hasmatch = false;
		for (std::vector<std::string>::const_iterator it = keys.begin(); it != keys.end(); ++it)
		{
			const MetadataKeyMap::const_iterator entry = map->find(*it);
			if (entry == map->end())
				continue;
			const IRCv3::Metadata::KeyDefinition* def = settings.FindDefinition(*it);
			if (!HasKeyViewPermission(viewer, target, def))
				continue;
			hasmatch = true;
			break;
		}
		if (!hasmatch)
			return;

		BatchScope scope(*this, target.name);
		for (std::vector<std::string>::const_iterator it = keys.begin(); it != keys.end(); ++it)
		{
			const MetadataKeyMap::const_iterator entry = map->find(*it);
			if (entry == map->end())
				continue;
			const IRCv3::Metadata::KeyDefinition* def = settings.FindDefinition(*it);
			if (!HasKeyViewPermission(viewer, target, def))
				continue;
			SendKeyValue(viewer, target, *it, entry->second);
		}
	}

	void SendSubscriptionSnapshot(LocalUser* user, const std::vector<std::string>& keys)
	{
		if (!capability.IsEnabled(user) || keys.empty())
			return;

		insp::flat_set<std::string> dedup;
		std::vector<std::string> uniq;
		uniq.reserve(keys.size());
		for (std::vector<std::string>::const_iterator it = keys.begin(); it != keys.end(); ++it)
		{
			if (dedup.insert(*it).second)
				uniq.push_back(*it);
		}
		if (uniq.empty())
			return;

		IRCv3::Metadata::Target selftarget;
		selftarget.ischannel = false;
		selftarget.user = user;
		selftarget.name = user->nick;
		SendKeysForTarget(user, selftarget, uniq);

		insp::flat_set<User*> seenusers;
		seenusers.insert(user);

		const User::ChanList& chans = user->chans;
		for (User::ChanList::const_iterator it = chans.begin(); it != chans.end(); ++it)
		{
			Membership* memb = *it;
			if (!memb || !memb->chan)
				continue;

			IRCv3::Metadata::Target chantarget;
			chantarget.ischannel = true;
			chantarget.chan = memb->chan;
			chantarget.name = chantarget.chan->name;
			SendKeysForTarget(user, chantarget, uniq);

			const Channel::MemberMap& members = chantarget.chan->GetUsers();
			for (Channel::MemberMap::const_iterator mem = members.begin(); mem != members.end(); ++mem)
			{
				User* member = mem->first;
				if (!member || !seenusers.insert(member).second)
					continue;

				IRCv3::Metadata::Target usertarget;
				usertarget.ischannel = false;
				usertarget.user = member;
				usertarget.name = member->nick;
				SendKeysForTarget(user, usertarget, uniq);
			}
		}
	}

	class NeighborNotifier final : public User::ForEachNeighborHandler
	{
		CommandMetadata& cmd;
		ClientProtocol::Event& protoev;
		const IRCv3::Metadata::Target& target;
		const std::string& key;
		uint64_t sentid;

		void Execute(LocalUser* user) override
		{
			if (cmd.ShouldDeliver(user, target, key))
				user->Send(protoev);
		}

	 public:
		NeighborNotifier(CommandMetadata& Cmd, User* source, ClientProtocol::Event& ev, const IRCv3::Metadata::Target& Target, const std::string& Key)
			: cmd(Cmd)
			, protoev(ev)
			, target(Target)
			, key(Key)
		{
			sentid = source->ForEachNeighbor(*this, false);
		}

		uint64_t GetAlreadySentId() const { return sentid; }
	};

	class WatcherNotifier final : public Monitor::ForEachHandler
	{
		CommandMetadata& cmd;
		ClientProtocol::Event& protoev;
		const IRCv3::Metadata::Target& target;
		const std::string& key;
		const uint64_t sentid;

		void Execute(LocalUser* user) override
		{
			if (user->already_sent == sentid)
				return;

			if (!cmd.ShouldDeliver(user, target, key))
				return;

			user->already_sent = sentid;
			user->Send(protoev);
		}

	 public:
		WatcherNotifier(CommandMetadata& Cmd, ClientProtocol::Event& ev, const IRCv3::Metadata::Target& Target, const std::string& Key, uint64_t SentId)
			: cmd(Cmd)
			, protoev(ev)
			, target(Target)
			, key(Key)
			, sentid(SentId)
		{
		}
	};

	struct BatchScope
	{
		CommandMetadata& cmd;
		bool active;

		BatchScope(CommandMetadata& Cmd, const std::string& target)
			: cmd(Cmd)
			, active(false)
		{
			if (!cmd.batchapi)
				return;

			cmd.batchapi->Start(cmd.metadatabatch);

			if (!cmd.metadatabatch.IsRunning())
				return;

			ClientProtocol::Message& batchstartmsg = cmd.metadatabatch.GetBatchStartMessage();
			if (batchstartmsg.GetParams().size() < 3)
				batchstartmsg.PushParam(target);
			else
				batchstartmsg.ReplaceParam(2, target);

			active = true;
		}

		~BatchScope()
		{
			if (active && cmd.batchapi)
				cmd.batchapi->End(cmd.metadatabatch);
		}
	};

	bool ResolveTarget(LocalUser* user, const std::string& targetname, IRCv3::Metadata::Target& out)
	{
		if (targetname == "*")
		{
			out.ischannel = false;
			out.user = user;
			out.name = user->nick;
			return true;
		}

		if (!targetname.empty() && targetname[0] == '#')
		{
			Channel* chan = ServerInstance->Channels.Find(targetname);
			if (!chan)
			{
				SendFail(user, "INVALID_TARGET", targetname, "Invalid metadata target");
				return false;
			}
			out.ischannel = true;
			out.chan = chan;
			out.name = chan->name;
			return true;
		}

		User* targetuser = ServerInstance->Users.FindNick(targetname);
		if (!targetuser || !targetuser->IsFullyConnected())
		{
			SendFail(user, "INVALID_TARGET", targetname, "Invalid metadata target");
			return false;
		}
		out.ischannel = false;
		out.user = targetuser;
		out.name = targetuser->nick;
		return true;
	}

	bool HasOperMetadataPriv(LocalUser* user, bool channel) const
	{
		return user->HasPrivPermission(channel ? "channels/metadata" : "users/metadata");
	}

	bool AllowServiceOverride(LocalUser* user) const
	{
		return user->HasPrivPermission("users/metadata/service");
	}

	bool CanView(LocalUser* user, const IRCv3::Metadata::Target& target) const
	{
		if (target.ischannel)
		{
			if (target.chan->HasUser(user))
				return true;
			return user->HasPrivPermission("channels/auspex");
		}

		if (target.user == user)
			return true;
		if (target.user->SharesChannelWith(user))
			return true;
		return user->HasPrivPermission("users/auspex");
	}

	bool CanSet(LocalUser* user, const IRCv3::Metadata::Target& target, const IRCv3::Metadata::KeyDefinition* def) const
	{
		if (AllowServiceOverride(user))
			return true;

		if (def)
		{
			if (def->servicesonly)
				return false;
			if (!def->setpriv.empty() && !user->HasPrivPermission(def->setpriv))
				return false;
		}

		if (target.ischannel)
		{
			if (target.chan->HasUser(user) && target.chan->GetPrefixValue(user) >= OP_VALUE)
				return true;
			return HasOperMetadataPriv(user, true);
		}

		if (target.user == user)
			return true;

		if (def && def->operonly)
			return HasOperMetadataPriv(user, false);

		return HasOperMetadataPriv(user, false);
	}

	bool HasKeyViewPermission(LocalUser* user, const IRCv3::Metadata::Target& target, const IRCv3::Metadata::KeyDefinition* def) const
	{
		if (!def || def->viewpriv.empty())
			return true;

		if (!target.ischannel && target.user == user)
			return true;

		if (AllowServiceOverride(user))
			return true;

		return user->HasPrivPermission(def->viewpriv);
	}

	bool CanModifyTarget(LocalUser* user, const IRCv3::Metadata::Target& target) const
	{
		if (target.ischannel)
		{
			if (target.chan->HasUser(user) && target.chan->GetPrefixValue(user) >= OP_VALUE)
				return true;
			return HasOperMetadataPriv(user, true);
		}

		if (target.user == user)
			return true;
		return HasOperMetadataPriv(user, false);
	}

	const IRCv3::Metadata::KeyDefinition* ResolveKeyDefinition(const std::string& key, bool allowunknown)
	{
		const IRCv3::Metadata::KeyDefinition* def = settings.FindDefinition(key);
		if (!def && !allowunknown)
			return NULL;
		return def;
	}

	void MaybeUnset(const IRCv3::Metadata::Target& target)
	{
		if (target.ischannel)
			store.MaybeUnset(target.chan);
		else
			store.MaybeUnset(target.user);
	}

	void SendKeyValue(LocalUser* user, const IRCv3::Metadata::Target& target, const std::string& key, const IRCv3::Metadata::Entry& entry)
	{
		Numeric::Numeric numeric(RPL_KEYVALUE);
		numeric.push(target.name);
		numeric.push(key);
		numeric.push(entry.visibility.empty() ? "*" : entry.visibility);
		numeric.push(entry.value);

		ClientProtocol::Messages::Numeric numericmsg(numeric, user);
		metadatabatch.AddToBatch(numericmsg);
		user->Send(ServerInstance->GetRFCEvents().numeric, numericmsg);
	}

	void SendKeyNotSet(LocalUser* user, const IRCv3::Metadata::Target& target, const std::string& key)
	{
		Numeric::Numeric numeric(RPL_KEYNOTSET);
		numeric.push(target.name);
		numeric.push(key);
		numeric.push("Key not set");

		ClientProtocol::Messages::Numeric numericmsg(numeric, user);
		metadatabatch.AddToBatch(numericmsg);
		user->Send(ServerInstance->GetRFCEvents().numeric, numericmsg);
	}

	bool CheckRateLimit(LocalUser* user, const std::string& target, const std::string& key)
	{
		if (!requestlimit || !requestwindow)
			return true;

		RequestCounter& counter = requests[user];
		const time_t now = ServerInstance->Time();
		if (counter.window + requestwindow <= now)
		{
			counter.window = now;
			counter.count = 0;
		}
		else if (counter.count >= requestlimit)
		{
			time_t wait = (counter.window + requestwindow) - now;
			if (wait <= 0)
				wait = requestwindow;
			SendFail(user, "RATE_LIMITED", target, key.empty() ? "*" : key, wait, "Too many metadata requests");
			return false;
		}

		counter.count++;
		return true;
	}

	CmdResult HandleGet(LocalUser* user, const Params& parameters)
	{
		if (parameters.size() < 3)
		{
			user->WriteNumeric(ERR_NEEDMOREPARAMS, name, "Not enough parameters");
			return CmdResult::FAILURE;
		}

		IRCv3::Metadata::Target target;
		if (!ResolveTarget(user, parameters[0], target))
			return CmdResult::FAILURE;

		if (!CanView(user, target))
		{
			SendFail(user, "KEY_NO_PERMISSION", target.name, "*", "You do not have permission to view metadata on this target");
			return CmdResult::FAILURE;
		}

		if (!CheckRateLimit(user, target.name, parameters[2]))
			return CmdResult::FAILURE;

		const MetadataKeyMap* map = target.PeekMap(store);
		BatchScope scope(*this, target.name);

		for (size_t i = 2; i < parameters.size(); ++i)
		{
			const std::string& key = parameters[i];
			if (!IsValidMetadataKey(key))
			{
				SendFail(user, "KEY_INVALID", key, "Invalid metadata key");
				continue;
			}

			const IRCv3::Metadata::KeyDefinition* def = settings.FindDefinition(key);
			if (!HasKeyViewPermission(user, target, def))
			{
				SendFail(user, "KEY_NO_PERMISSION", target.name, key, "You do not have permission to view this key");
				continue;
			}

			const MetadataKeyMap::const_iterator it = map ? map->find(key) : MetadataKeyMap::const_iterator();
			if (!map || it == map->end())
				SendKeyNotSet(user, target, key);
			else
				SendKeyValue(user, target, key, it->second);
		}

		return CmdResult::SUCCESS;
	}

	CmdResult HandleList(LocalUser* user, const Params& parameters)
	{
		IRCv3::Metadata::Target target;
		if (!ResolveTarget(user, parameters[0], target))
			return CmdResult::FAILURE;

		if (!CanView(user, target))
		{
			SendFail(user, "KEY_NO_PERMISSION", target.name, "*", "You do not have permission to view metadata on this target");
			return CmdResult::FAILURE;
		}

		if (!CheckRateLimit(user, target.name, "*"))
			return CmdResult::FAILURE;

		const MetadataKeyMap* map = target.PeekMap(store);
		if (!map || map->empty())
		{
			BatchScope scope(*this, target.name);
			return CmdResult::SUCCESS;
		}

		BatchScope scope(*this, target.name);
		for (MetadataKeyMap::const_iterator it = map->begin(); it != map->end(); ++it)
		{
			const IRCv3::Metadata::KeyDefinition* def = settings.FindDefinition(it->first);
			if (!HasKeyViewPermission(user, target, def))
			{
				SendFail(user, "KEY_NO_PERMISSION", target.name, it->first, "You do not have permission to view this key");
				continue;
			}
			SendKeyValue(user, target, it->first, it->second);
		}
		return CmdResult::SUCCESS;
	}

	CmdResult HandleSet(LocalUser* user, const Params& parameters)
	{
		if (parameters.size() < 3)
		{
			user->WriteNumeric(ERR_NEEDMOREPARAMS, name, "Not enough parameters");
			return CmdResult::FAILURE;
		}

		IRCv3::Metadata::Target target;
		if (!ResolveTarget(user, parameters[0], target))
			return CmdResult::FAILURE;

		const std::string& key = parameters[2];
		if (!IsValidMetadataKey(key))
		{
			SendFail(user, "KEY_INVALID", key, "Invalid metadata key");
			return CmdResult::FAILURE;
		}

		const IRCv3::Metadata::KeyDefinition* def = ResolveKeyDefinition(key, settings.allowunknownkeys);
		if (!def && !settings.allowunknownkeys)
		{
			SendFail(user, "KEY_INVALID", key, "Unknown metadata key");
			return CmdResult::FAILURE;
		}
		if (def && !def->AllowsTarget(target.ischannel))
		{
			SendFail(user, "KEY_INVALID", key, "Key does not apply to this target");
			return CmdResult::FAILURE;
		}

		if (!CanSet(user, target, def))
		{
			SendFail(user, "KEY_NO_PERMISSION", target.name, key, "You do not have permission to set this key");
			return CmdResult::FAILURE;
		}

		if (!CheckRateLimit(user, target.name, key))
			return CmdResult::FAILURE;

		const bool removing = (parameters.size() < 4);
		std::string value;
		if (!removing)
			value = parameters[3];

		MetadataKeyMap* map = target.GetMap(store, !removing);
		MetadataKeyMap::iterator it = (map ? map->find(key) : MetadataKeyMap::iterator());

		if (removing)
		{
			if (!map || it == map->end())
			{
				SendFail(user, "KEY_NOT_SET", target.name, key, "Key is not set");
				return CmdResult::FAILURE;
			}

			value = it->second.value;
		}

		ModResult modres = hookprov.FirstResult<IRCv3::Metadata::EventListener>(
			&IRCv3::Metadata::EventListener::OnPreMetadataSet, user, target, key, value, removing);
		if (modres == MOD_RES_DENY)
		{
			SendFail(user, "KEY_NO_PERMISSION", target.name, key, "Metadata change blocked");
			return CmdResult::FAILURE;
		}

		if (!removing && value.size() > settings.maxvaluebytes)
		{
			SendFail(user, "VALUE_INVALID", "Value is too long");
			return CmdResult::FAILURE;
		}

		if (removing)
		{
			IRCv3::Metadata::Entry removed = it->second;
			map->erase(it);

			MaybeUnset(target);
			BatchScope scope(*this, target.name);
			SendKeyNotSet(user, target, key);

			if (target.ischannel)
				ServerInstance->PI->SendMetadata(target.chan, key, "");
			else
				ServerInstance->PI->SendMetadata(target.user, key, "");

			removed.value.clear();
			BroadcastMetadataChange(user, target, key, &removed, (target.user == user), true);
			return CmdResult::SUCCESS;
		}

		IRCv3::Metadata::Entry& entry = (*map)[key];
		entry.value = value;
		entry.visibility = (def ? def->visibility : settings.defaultvisibility);
		entry.updated = ServerInstance->Time();

		if (settings.maxkeys && (map->size() > settings.maxkeys) && !AllowServiceOverride(user))
		{
			map->erase(key);
			MaybeUnset(target);
			SendFail(user, "LIMIT_REACHED", target.name, "Metadata limit reached");
			return CmdResult::FAILURE;
		}

		BatchScope scope(*this, target.name);
		SendKeyValue(user, target, key, entry);

		if (target.ischannel)
			ServerInstance->PI->SendMetadata(target.chan, key, entry.value);
		else
			ServerInstance->PI->SendMetadata(target.user, key, entry.value);

		BroadcastMetadataChange(user, target, key, &entry, (target.user == user), false);
		return CmdResult::SUCCESS;
	}

	CmdResult HandleClear(LocalUser* user, const Params& parameters)
	{
		IRCv3::Metadata::Target target;
		if (!ResolveTarget(user, parameters[0], target))
			return CmdResult::FAILURE;

		if (!CanModifyTarget(user, target))
		{
			SendFail(user, "KEY_NO_PERMISSION", target.name, "*", "You do not have permission to modify metadata on this target");
			return CmdResult::FAILURE;
		}

		if (!CheckRateLimit(user, target.name, "*"))
			return CmdResult::FAILURE;

		MetadataKeyMap* map = target.GetMap(store, false);
		if (!map || map->empty())
		{
			BatchScope scope(*this, target.name);
			return CmdResult::SUCCESS;
		}

		std::vector<std::pair<std::string, IRCv3::Metadata::Entry> > entries;
		entries.reserve(map->size());
		for (MetadataKeyMap::const_iterator it = map->begin(); it != map->end(); ++it)
			entries.push_back(*it);

		map->clear();
		MaybeUnset(target);

		BatchScope scope(*this, target.name);
		for (std::vector<std::pair<std::string, IRCv3::Metadata::Entry> >::iterator it = entries.begin(); it != entries.end(); ++it)
		{
			it->second.value.clear();
			SendKeyValue(user, target, it->first, it->second);

			if (target.ischannel)
				ServerInstance->PI->SendMetadata(target.chan, it->first, "");
			else
				ServerInstance->PI->SendMetadata(target.user, it->first, "");

			BroadcastMetadataChange(user, target, it->first, &it->second, (target.user == user), true);
		}

		return CmdResult::SUCCESS;
	}

	void SendAllMetadata(LocalUser* user, const IRCv3::Metadata::Target& target)
	{
		const MetadataKeyMap* map = target.PeekMap(store);
		if (!map)
			return;

		for (MetadataKeyMap::const_iterator it = map->begin(); it != map->end(); ++it)
			SendKeyValue(user, target, it->first, it->second);
	}

	CmdResult HandleSync(LocalUser* user, const Params& parameters)
	{
		IRCv3::Metadata::Target target;
		if (!ResolveTarget(user, parameters[0], target))
			return CmdResult::FAILURE;

		if (!CanView(user, target))
		{
			SendFail(user, "KEY_NO_PERMISSION", target.name, "*", "You do not have permission to view metadata on this target");
			return CmdResult::FAILURE;
		}

		if (!CheckRateLimit(user, target.name, "*"))
			return CmdResult::FAILURE;

		time_t wait = 0;
		if (!CheckSyncReady(user, target.name, wait))
		{
			SendSyncLaterNumeric(user, target.name, wait ? wait : GetRetryDelay());
			return CmdResult::FAILURE;
		}

		BatchScope scope(*this, target.name);
		SendAllMetadata(user, target);

		if (!target.ischannel)
		{
			ClearSyncSchedule(user, target.name);
			return CmdResult::SUCCESS;
		}

		const Channel::MemberMap& members = target.chan->GetUsers();
		for (Channel::MemberMap::const_iterator it = members.begin(); it != members.end(); ++it)
		{
			User* member = it->first;
			if (!member)
				continue;

			IRCv3::Metadata::Target usertarget;
			usertarget.ischannel = false;
			usertarget.user = member;
			usertarget.name = member->nick;

			const MetadataKeyMap* map = usertarget.PeekMap(store);
			if (!map || map->empty())
				continue;

			if (!CanView(user, usertarget))
				continue;

			for (MetadataKeyMap::const_iterator key = map->begin(); key != map->end(); ++key)
				SendKeyValue(user, usertarget, key->first, key->second);
		}

		ClearSyncSchedule(user, target.name);
		return CmdResult::SUCCESS;
	}

 public:
	void SendOwnMetadata(LocalUser* user)
	{
		if (!capability.IsEnabled(user))
			return;

		IRCv3::Metadata::Target target;
		target.ischannel = false;
		target.user = user;
		target.name = user->nick;

		const MetadataKeyMap* map = target.PeekMap(store);
		const unsigned int entries = map ? static_cast<unsigned int>(map->size()) : 0;
		if (entries && MaybeDeferSync(user, target, entries))
			return;

		BatchScope scope(*this, target.name);
		SendAllMetadata(user, target);
	}

	void SendChannelMetadata(LocalUser* user, Channel* chan)
	{
		if (!capability.IsEnabled(user))
			return;

		IRCv3::Metadata::Target target;
		target.ischannel = true;
		target.chan = chan;
		target.name = chan->name;

		if (settings.autosyncthreshold)
		{
			const unsigned int total = CountChannelEntries(chan, settings.autosyncthreshold);
			if (total && MaybeDeferSync(user, target, total))
				return;
		}

		BatchScope scope(*this, target.name);
		SendAllMetadata(user, target);

		const Channel::MemberMap& members = chan->GetUsers();
		for (Channel::MemberMap::const_iterator it = members.begin(); it != members.end(); ++it)
		{
			User* member = it->first;
			if (!member)
				continue;

			IRCv3::Metadata::Target usertarget;
			usertarget.ischannel = false;
			usertarget.user = member;
			usertarget.name = member->nick;

			const MetadataKeyMap* map = usertarget.PeekMap(store);
			if (!map || map->empty())
				continue;

			for (MetadataKeyMap::const_iterator key = map->begin(); key != map->end(); ++key)
			{
				const IRCv3::Metadata::KeyDefinition* def = settings.FindDefinition(key->first);
				if (!HasKeyViewPermission(user, usertarget, def))
					continue;
				SendKeyValue(user, usertarget, key->first, key->second);
			}
		}
	}

	void BroadcastMetadataChange(User* setter, const IRCv3::Metadata::Target& target, const std::string& key, const IRCv3::Metadata::Entry* entry, bool selfchange, bool removing)
	{
		ClientProtocol::Message msg("METADATA", setter ? setter : ServerInstance->FakeClient);
		msg.PushParamRef(target.name);
		msg.PushParamRef(key);
		msg.PushParam(entry ? entry->visibility : "*");
		if (entry)
			msg.PushParam(entry->value);
		else
			msg.PushParam("");

		ClientProtocol::Event protoev(metadataevprov, msg);

		IRCv3::Metadata::TargetInfo hooktarget;
		hooktarget.name = target.name;
		hooktarget.user = target.user;
		hooktarget.chan = target.chan;
		hooktarget.ischannel = target.ischannel;
		const std::string hookvalue = (entry ? entry->value : std::string());
		hookprov.Call<IRCv3::Metadata::EventListener>(
			&IRCv3::Metadata::EventListener::OnMetadataChanged, setter, hooktarget, key, hookvalue, removing);

		if (target.ischannel)
		{
			const uint64_t sentid = ServerInstance->Users.NextAlreadySentId();
			const Channel::MemberMap& users = target.chan->GetUsers();
			for (Channel::MemberMap::const_iterator it = users.begin(); it != users.end(); ++it)
			{
				LocalUser* localuser = IS_LOCAL(it->first);
				if (!localuser || localuser->already_sent == sentid)
					continue;
				if (!ShouldDeliver(localuser, target, key))
					continue;

				localuser->already_sent = sentid;
				localuser->Send(protoev);
			}
			return;
		}

		if (!target.user)
			return;

		NeighborNotifier neighbors(*this, target.user, protoev, target, key);
		const uint64_t sentid = neighbors.GetAlreadySentId();

		LocalUser* localtarget = IS_LOCAL(target.user);
		if (localtarget && !selfchange && localtarget->already_sent != sentid && ShouldDeliver(localtarget, target, key))
		{
			localtarget->already_sent = sentid;
			localtarget->Send(protoev);
		}

		if (monitorapi)
		{
			WatcherNotifier watcher(*this, protoev, target, key, sentid);
			monitorapi->ForEachWatcher(target.user, watcher, false);
		}
	}

	void ForgetRateLimit(LocalUser* user)
	{
		requests.erase(user);
	}

	void ForgetSyncs(LocalUser* user)
	{
		deferredsyncs.erase(user);
	}

	void ApplyRemoteUpdate(User* setter, Extensible* ext, const std::string& key, const std::string& value)
	{
		if (!ext)
			return;

		IRCv3::Metadata::Target target;
		switch (ext->extype)
		{
			case ExtensionType::CHANNEL:
			{
				target.ischannel = true;
				target.chan = static_cast<Channel*>(ext);
				target.name = target.chan->name;
				break;
			}
			case ExtensionType::USER:
			{
				target.ischannel = false;
				target.user = static_cast<User*>(ext);
				target.name = target.user->nick;
				break;
			}
			default:
				return;
		}

		if (value.empty())
		{
			MetadataKeyMap* map = target.GetMap(store, false);
			if (!map)
				return;

			MetadataKeyMap::iterator it = map->find(key);
			if (it == map->end())
				return;

			IRCv3::Metadata::Entry removed = it->second;
			map->erase(it);
			MaybeUnset(target);
			removed.value.clear();
			BroadcastMetadataChange(setter, target, key, &removed, false, true);
			return;
		}

		MetadataKeyMap* map = target.GetMap(store, true);
		IRCv3::Metadata::Entry& entry = (*map)[key];
		entry.value = value;
		entry.visibility = settings.defaultvisibility;
		entry.updated = ServerInstance->Time();
		BroadcastMetadataChange(setter, target, key, &entry, false, false);
	}

 public:
	CommandMetadata(Module* parent, IRCv3::Metadata::Settings& settingsref, IRCv3::Metadata::Store& storeref,
		IRCv3::Metadata::SubscriptionStore& subsref, Cap::Capability& capref,
		ClientProtocol::EventProvider& protoev, Events::ModuleEventProvider& hookref,
		Monitor::API& monitorref)
		: SplitCommand(parent, "METADATA", 2)
		, settings(settingsref)
		, store(storeref)
		, subscriptions(subsref)
		, capability(capref)
		, metadataevprov(protoev)
		, hookprov(hookref)
		, monitorapi(monitorref)
		, failreply(parent)
		, repliescap(parent)
		, batchapi(parent)
		, subsbatch("metadata-subs")
		, metadatabatch("metadata")
		{
			syntax = { "<target> <subcommand> [parameters]" };
			allow_empty_last_param = true;
			RefreshLimits();
		}

		void RefreshLimits()
		{
			requestlimit = settings.ratelimitrequests;
			requestwindow = settings.ratelimitwindow;
		}

		void SetBeforeConnect(bool enabled)
		{
			works_before_reg = enabled;
		}

	CmdResult HandleLocal(LocalUser* user, const Params& parameters) override
	{
		if (parameters.size() < 2)
		{
			user->WriteNumeric(ERR_NEEDMOREPARAMS, name, "Not enough parameters");
			return CmdResult::FAILURE;
		}

		const bool prereg = !user->IsFullyConnected();
		if (prereg)
		{
			if (!settings.beforeconnect)
				return CmdResult::FAILURE;

			if (parameters[0] != "*")
			{
				SendFail(user, "INVALID_TARGET", parameters[0], "You must target yourself before registration");
				return CmdResult::FAILURE;
			}
		}

		const std::string& subcmd = parameters[1];
		if (irc::equals(subcmd, "SUB"))
			return HandleSub(user, parameters);

		if (irc::equals(subcmd, "UNSUB"))
			return HandleUnsub(user, parameters);

		if (irc::equals(subcmd, "SUBS"))
			return HandleSubs(user, parameters);

		if (irc::equals(subcmd, "GET"))
			return HandleGet(user, parameters);

		if (irc::equals(subcmd, "LIST"))
			return HandleList(user, parameters);

		if (irc::equals(subcmd, "SET"))
			return HandleSet(user, parameters);

		if (irc::equals(subcmd, "CLEAR"))
			return HandleClear(user, parameters);

		if (irc::equals(subcmd, "SYNC"))
			return HandleSync(user, parameters);

		SendFail(user, "SUBCOMMAND_INVALID", subcmd, "Unknown METADATA subcommand");
		return CmdResult::FAILURE;
	}
};

MetadataKeyMap* IRCv3::Metadata::Target::GetMap(IRCv3::Metadata::Store& store, bool create) const
{
	return ischannel ? store.Get(chan, create) : store.Get(user, create);
}

const MetadataKeyMap* IRCv3::Metadata::Target::PeekMap(const IRCv3::Metadata::Store& store) const
{
	return ischannel ? store.Peek(chan) : store.Peek(user);
}

class ModuleIRCv3Metadata final
	: public Module
	, public IRCv3::Metadata::APIBase
	, public ServerProtocol::SyncEventListener
{
	IRCv3::Metadata::Settings settings;
	MetadataCapability capability;
	ClientProtocol::EventProvider metadataevprov;
	Events::ModuleEventProvider hookprov;
	Monitor::API monitorapi;
	IRCv3::Metadata::Store store;
	IRCv3::Metadata::SubscriptionStore subscriptions;
	CommandMetadata cmd;

 public:
	ModuleIRCv3Metadata()
		: Module(VF_VENDOR | VF_OPTCOMMON, "Implements the IRCv3 draft/metadata-2 capability.")
		, IRCv3::Metadata::APIBase(this)
		, ServerProtocol::SyncEventListener(this)
		, capability(this, settings)
		, metadataevprov(this, "METADATA")
		, hookprov(this, "event/ircv3-metadata")
		, monitorapi(this)
		, store(this)
		, subscriptions(this)
		, cmd(this, settings, store, subscriptions, capability, metadataevprov, hookprov, monitorapi)
	{
	}

	void ReadConfig(ConfigStatus& status) override
	{
		const auto& tag = ServerInstance->Config->ConfValue("ircv3metadata");
		settings.ReadGeneral(tag.get());
		settings.ReadKeys(this, ServerInstance->Config->ConfTags("ircv3metadatakey"));
		cmd.RefreshLimits();
		cmd.SetBeforeConnect(settings.beforeconnect);
	}

	bool RegisterKey(Module* owner, const IRCv3::Metadata::KeySpec& spec) override
	{
		return settings.RegisterDynamicKey(owner, spec);
	}

	void UnregisterKeys(Module* owner) override
	{
		settings.RemoveKeysOwnedBy(owner);
	}

	bool SetKey(User* user, const std::string& key, const std::string& value) override
	{
		if (!user || key.empty() || !IsValidMetadataKey(key))
			return false;

		IRCv3::Metadata::Target target;
		target.ischannel = false;
		target.user = user;
		target.name = user->nick;

		MetadataKeyMap* map = store.Get(user, true);
		IRCv3::Metadata::Entry& entry = (*map)[key];
		entry.value = value;
		entry.visibility = settings.defaultvisibility;
		entry.updated = ServerInstance->Time();

		ServerInstance->PI->SendMetadata(user, key, value);
		cmd.BroadcastMetadataChange(nullptr, target, key, &entry, false, false);
		return true;
	}

	bool SetKey(Channel* chan, const std::string& key, const std::string& value) override
	{
		if (!chan || key.empty() || !IsValidMetadataKey(key))
			return false;

		IRCv3::Metadata::Target target;
		target.ischannel = true;
		target.chan = chan;
		target.name = chan->name;

		MetadataKeyMap* map = store.Get(chan, true);
		IRCv3::Metadata::Entry& entry = (*map)[key];
		entry.value = value;
		entry.visibility = settings.defaultvisibility;
		entry.updated = ServerInstance->Time();

		ServerInstance->PI->SendMetadata(chan, key, value);
		cmd.BroadcastMetadataChange(nullptr, target, key, &entry, false, false);
		return true;
	}

	bool UnsetKey(User* user, const std::string& key) override
	{
		if (!user || key.empty())
			return false;

		MetadataKeyMap* map = store.Get(user, false);
		if (!map)
			return false;

		MetadataKeyMap::iterator it = map->find(key);
		if (it == map->end())
			return false;

		IRCv3::Metadata::Target target;
		target.ischannel = false;
		target.user = user;
		target.name = user->nick;

		IRCv3::Metadata::Entry removed = it->second;
		map->erase(it);
		store.MaybeUnset(user);

		ServerInstance->PI->SendMetadata(user, key, "");
		removed.value.clear();
		cmd.BroadcastMetadataChange(nullptr, target, key, &removed, false, true);
		return true;
	}

	bool UnsetKey(Channel* chan, const std::string& key) override
	{
		if (!chan || key.empty())
			return false;

		MetadataKeyMap* map = store.Get(chan, false);
		if (!map)
			return false;

		MetadataKeyMap::iterator it = map->find(key);
		if (it == map->end())
			return false;

		IRCv3::Metadata::Target target;
		target.ischannel = true;
		target.chan = chan;
		target.name = chan->name;

		IRCv3::Metadata::Entry removed = it->second;
		map->erase(it);
		store.MaybeUnset(chan);

		ServerInstance->PI->SendMetadata(chan, key, "");
		removed.value.clear();
		cmd.BroadcastMetadataChange(nullptr, target, key, &removed, false, true);
		return true;
	}

	std::string GetKey(User* user, const std::string& key) const override
	{
		if (!user || key.empty())
			return "";

		const MetadataKeyMap* map = store.Peek(user);
		if (!map)
			return "";

		MetadataKeyMap::const_iterator it = map->find(key);
		if (it == map->end())
			return "";

		return it->second.value;
	}

	std::string GetKey(Channel* chan, const std::string& key) const override
	{
		if (!chan || key.empty())
			return "";

		const MetadataKeyMap* map = store.Peek(chan);
		if (!map)
			return "";

		MetadataKeyMap::const_iterator it = map->find(key);
		if (it == map->end())
			return "";

		return it->second.value;
	}

	void OnUnloadModule(Module* mod) override
	{
		settings.RemoveKeysOwnedBy(mod);
	}

	ModResult OnUserRegister(LocalUser* user) override
	{
		cmd.SendOwnMetadata(user);
		return MOD_RES_PASSTHRU;
	}

	void OnPostJoin(Membership* memb) override
	{
		LocalUser* local = IS_LOCAL(memb->user);
		if (!local)
			return;
		cmd.SendChannelMetadata(local, memb->chan);
	}

	void OnUserDisconnect(LocalUser* user) override
	{
		cmd.ForgetRateLimit(user);
		cmd.ForgetSyncs(user);
	}

	void OnDecodeMetadata(Extensible* target, const std::string& extname, const std::string& extdata) override
	{
		if (extname.empty())
			return;

		cmd.ApplyRemoteUpdate(NULL, target, extname, extdata);
	}

	void OnSyncUser(User* user, Server& server) override
	{
		const MetadataKeyMap* map = store.Peek(user);
		if (!map || map->empty())
			return;

		for (MetadataKeyMap::const_iterator it = map->begin(); it != map->end(); ++it)
			server.SendMetadata(user, it->first, it->second.value);
	}

	void OnSyncChannel(Channel* chan, Server& server) override
	{
		const MetadataKeyMap* map = store.Peek(chan);
		if (!map || map->empty())
			return;

		for (MetadataKeyMap::const_iterator it = map->begin(); it != map->end(); ++it)
			server.SendMetadata(chan, it->first, it->second.value);
	}

};

MODULE_INIT(ModuleIRCv3Metadata)
