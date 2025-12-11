/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2024 RelayOS
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

/// $ModAuthor: RelayOS
/// $ModDesc: Sets IRCv3 metadata from WEBIRC flags.
/// $ModDepends: core 4

#include "inspircd.h"
#include "extension.h"
#include "modules/ircv3_metadata.h"
#include "modules/webirc.h"

class ModuleWebIRCMetadata final
	: public Module
	, public WebIRC::EventListener
{
private:
	IRCv3::Metadata::API metaapi;
	std::vector<std::string> keys;
	std::set<std::string> registeredkeys;
	SimpleExtItem<WebIRC::FlagMap> flagsext;
	bool apiwarned = false;

	bool EnsureAPI()
	{
		if (!metaapi)
		{
			if (!apiwarned)
			{
				ServerInstance->Logs.Warning(MODNAME, "The ircv3_metadata module must be loaded for this module to work.");
				apiwarned = true;
			}
			return false;
		}
		return true;
	}

	void RegisterKey(const std::string& key)
	{
		if (!EnsureAPI())
			return;

		if (registeredkeys.count(key))
			return;

		IRCv3::Metadata::KeySpec spec;
		spec.name = key;
		spec.targets = IRCv3::Metadata::TARGET_USER;
		spec.servicesonly = true;
		metaapi->RegisterKey(this, spec);
		registeredkeys.insert(key);
		ServerInstance->Logs.Debug(MODNAME, "Registered metadata key: {}", key);
	}

public:
	ModuleWebIRCMetadata()
		: Module(VF_VENDOR | VF_OPTCOMMON, "Sets IRCv3 metadata keys from WEBIRC flags.")
		, WebIRC::EventListener(this)
		, metaapi(this)
		, flagsext(this, "webirc-metadata-flags", ExtensionType::USER)
	{
	}

	void ReadConfig(ConfigStatus& status) override
	{
		std::vector<std::string> newkeys;

		for (const auto& [_, tag] : ServerInstance->Config->ConfTags("webircmeta"))
		{
			const std::string key = tag->getString("key");
			if (key.empty())
				throw ModuleException(this, "<webircmeta:key> is a mandatory field, at " + tag->source.str());

			newkeys.push_back(key);
		}

		// Register all keys from config with the metadata API
		for (const auto& key : newkeys)
			RegisterKey(key);

		keys.swap(newkeys);

		ServerInstance->Logs.Debug(MODNAME, "Loaded {} webircmeta keys", keys.size());
	}

	void OnWebIRCAuth(LocalUser* user, const WebIRC::FlagMap* flags) override
	{
		if (!user || !flags || flags->empty())
			return;

		if (keys.empty())
			return;

		// Persist the flags we care about so we can apply them after the user is fully connected.
		WebIRC::FlagMap* filtered = new WebIRC::FlagMap();
		for (const auto& key : keys)
		{
			auto it = flags->find(key);
			if (it != flags->end() && !it->second.empty())
				(*filtered)[key] = it->second;
		}

		if (filtered->empty())
		{
			delete filtered;
			return;
		}

		flagsext.Set(user, filtered);
		ServerInstance->Logs.Debug(MODNAME, "Stored {} WEBIRC flags for user {}",
			filtered->size(), user->uuid);
	}

	void OnUserConnect(LocalUser* user) override
	{
		if (!user)
			return;

		if (!EnsureAPI())
			return;

		WebIRC::FlagMap* flags = flagsext.Get(user);
		if (!flags)
			return;

		for (const auto& [key, value] : *flags)
		{
			if (value.empty())
				continue;

			// Ensure key is registered before setting
			RegisterKey(key);

			metaapi->SetKey(user, key, value);
			ServerInstance->Logs.Debug(MODNAME, "Set metadata {}={} for user {}",
				key, value, user->uuid);
		}

		flagsext.Unset(user);
	}

	void OnUserDisconnect(LocalUser* user) override
	{
		if (!user)
			return;

		// Always clean up the extension item
		flagsext.Unset(user);

		if (!EnsureAPI())
			return;

		// Only unset keys that are actually registered
		for (const auto& key : registeredkeys)
			metaapi->UnsetKey(user, key);
	}
};

MODULE_INIT(ModuleWebIRCMetadata)
