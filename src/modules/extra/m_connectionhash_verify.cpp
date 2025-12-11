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
/// $ModDesc: Verifies connection/hash from WEBIRC flags, IRCv3 metadata, or GECOS JSON. Early rejection for anti-abuse.
/// $ModDepends: core 4
/// $CompilerFlags: find_compiler_flags("RapidJSON")
/// $PackageInfo: require_system("alpine") pkgconf rapidjson-dev
/// $PackageInfo: require_system("arch") pkgconf rapidjson
/// $PackageInfo: require_system("darwin") pkg-config rapidjson
/// $PackageInfo: require_system("debian~") rapidjson-dev pkg-config

#include "inspircd.h"
#include "extension.h"
#include "modules/hash.h"
#include "modules/webirc.h"

#include <rapidjson/document.h>

enum VerifyState
{
	VERIFY_PENDING,    // Not yet checked
	VERIFY_PASSED,     // Hash verified successfully
	VERIFY_FAILED,     // Hash verification failed
	VERIFY_SKIPPED     // No hash provided, allow through
};

class ModuleConnectionHashVerify final
	: public Module
	, public WebIRC::EventListener
{
private:
	SimpleExtItem<VerifyState> verifystate;
	StringExtItem webirchash;  // Store WEBIRC hash until IP is updated
	HashProvider* hasher = nullptr;
	std::string salt;
	std::string webirckey;   // WEBIRC flag key (e.g., "connection/hash")
	std::string gecoskey;    // GECOS JSON key (e.g., "ih")
	std::string kickreason;
	std::string mode;        // "webirc", "gecos", or "both"
	bool enabled = false;

	std::string GenerateHash(const std::string& ip) const
	{
		if (!hasher || ip.empty() || salt.empty())
			return "";

		std::string data = salt + ":" + ip;
		std::string digest = hasher->Generate(data);

		if (digest.length() < 11)
			return "";

		return digest.substr(0, 11);
	}

	// Extract hash from GECOS JSON {"ih":"hash",...}
	std::string ExtractGecosHash(LocalUser* user) const
	{
		if (!user)
			return "";

		std::string realname = user->GetRealName();
		if (realname.empty() || realname.length() > 512)
			return "";  // Sanity check: realnames shouldn't be huge

		rapidjson::Document doc;
		doc.Parse(realname.c_str());
		if (doc.HasParseError() || !doc.IsObject())
			return "";

		if (!doc.HasMember(gecoskey.c_str()))
			return "";

		const rapidjson::Value& field = doc[gecoskey.c_str()];
		if (!field.IsString())
			return "";

		return field.GetString();
	}

public:
	ModuleConnectionHashVerify()
		: Module(VF_VENDOR | VF_OPTCOMMON, "Verifies connection/hash from WEBIRC flags or GECOS JSON. Early rejection for anti-abuse.")
		, WebIRC::EventListener(this)
		, verifystate(this, "connhash-state", ExtensionType::USER)
		, webirchash(this, "connhash-webirc", ExtensionType::USER)
	{
	}

	void ReadConfig(ConfigStatus&) override
	{
		hasher = ServerInstance->Modules.FindDataService<HashProvider>("hash/sha256");

		const auto& tag = ServerInstance->Config->ConfValue("connectionhash");
		salt = tag->getString("salt");
		webirckey = tag->getString("key", "connection/hash");
		gecoskey = tag->getString("gecoskey", "ih");
		kickreason = tag->getString("reason", "Connection verification failed");
		mode = tag->getString("mode", "webirc");
		enabled = !salt.empty();

		// Validate mode
		if (mode != "webirc" && mode != "gecos" && mode != "both")
		{
			ServerInstance->Logs.Warning(MODNAME, "Invalid mode '{}', defaulting to 'webirc'", mode);
			mode = "webirc";
		}

		if (!enabled)
			ServerInstance->Logs.Warning(MODNAME, "No salt configured, module disabled");
		else
			ServerInstance->Logs.Debug(MODNAME, "Config: mode={} webirckey={} gecoskey={}", mode, webirckey, gecoskey);
	}

	// Store WEBIRC flags for later verification (IP isn't updated yet at this point)
	void OnWebIRCAuth(LocalUser* user, const WebIRC::FlagMap* flags) override
	{
		if (!user || !enabled || !flags)
			return;

		// Only store WEBIRC hash in webirc or both mode
		if (mode != "webirc" && mode != "both")
			return;

		// Look for our hash key in WEBIRC flags and store it for later
		auto it = flags->find(webirckey);
		if (it != flags->end())
		{
			// Store the provided hash - we'll verify it in OnUserRegister after IP is updated
			webirchash.Set(user, it->second);
			ServerInstance->Logs.Debug(MODNAME, "Stored WEBIRC hash for {} (will verify after IP update)",
				user->uuid);
		}
	}

	// EARLY CHECK: Called when NICK+USER complete (after IP has been updated by gateway)
	ModResult OnUserRegister(LocalUser* user) override
	{
		if (!user || !enabled)
			return MOD_RES_PASSTHRU;

		std::string expectedHash = GenerateHash(user->GetAddress());
		if (expectedHash.empty())
		{
			ServerInstance->Logs.Debug(MODNAME, "Cannot generate hash for {} ({}), allowing",
				user->nick, user->GetAddress());
			return MOD_RES_PASSTHRU;
		}

		bool verified = false;
		bool hashProvided = false;

		// Check stored WEBIRC hash (if mode is webirc or both)
		if (mode == "webirc" || mode == "both")
		{
			const std::string* storedHash = webirchash.Get(user);
			if (storedHash && !storedHash->empty())
			{
				hashProvided = true;
				if (*storedHash == expectedHash)
				{
					ServerInstance->Logs.Debug(MODNAME, "WEBIRC hash verified for {} ({})",
						user->nick, user->GetAddress());
					verified = true;
				}
				else
				{
					ServerInstance->Logs.Debug(MODNAME, "WEBIRC hash mismatch for {} ({}): got={} expected={}",
						user->nick, user->GetAddress(), *storedHash, expectedHash);
				}
			}
		}

		// Check GECOS if not yet verified (if mode is gecos or both)
		if (!verified && (mode == "gecos" || mode == "both"))
		{
			std::string gecosHash = ExtractGecosHash(user);
			if (!gecosHash.empty())
			{
				hashProvided = true;
				if (gecosHash == expectedHash)
				{
					ServerInstance->Logs.Debug(MODNAME, "GECOS hash verified for {} ({})",
						user->nick, user->GetAddress());
					verified = true;
				}
				else
				{
					ServerInstance->Logs.Debug(MODNAME, "GECOS hash mismatch for {} ({}): got={} expected={}",
						user->nick, user->GetAddress(), gecosHash, expectedHash);
				}
			}
		}

		// If no hash was provided, allow (non-WEBIRC client or gateway not configured)
		if (!hashProvided)
		{
			ServerInstance->Logs.Debug(MODNAME, "No hash provided for {} ({}), allowing",
				user->nick, user->GetAddress());
			return MOD_RES_PASSTHRU;
		}

		// Final decision
		if (!verified)
		{
			ServerInstance->Logs.Normal(MODNAME, "Hash verification failed for {} ({}) mode={}",
				user->nick, user->GetAddress(), mode);
			ServerInstance->Users.QuitUser(user, kickreason);
			return MOD_RES_DENY;
		}

		ServerInstance->Logs.Debug(MODNAME, "Hash verified for {} ({}) mode={}",
			user->nick, user->GetAddress(), mode);
		return MOD_RES_PASSTHRU;
	}

	void Prioritize() override
	{
		// Run after m_gateway so WEBIRC has been processed and IP has been updated
		Module* gateway = ServerInstance->Modules.Find("gateway");
		ServerInstance->Modules.SetPriority(this, I_OnUserRegister, PRIORITY_AFTER, gateway);
	}
};

MODULE_INIT(ModuleConnectionHashVerify)
