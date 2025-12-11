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

/// $PackageInfo: require_system("alpine") pkgconf rapidjson-dev
/// $PackageInfo: require_system("arch") pkgconf rapidjson
/// $PackageInfo: require_system("darwin") pkg-config rapidjson
/// $PackageInfo: require_system("debian~") rapidjson-dev pkg-config

#include "inspircd.h"
#include "modules/hash.h"

#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

class ModuleGecosJSON final
	: public Module
{
private:
	HashProvider* hasher;
	std::string salt;
	std::string kickreason;
	std::vector<std::string> classes;
	std::string mode;
	std::string usernamePattern;
	std::string hashKey;
	std::vector<std::string> stripFields;
	bool verifyhash; // explicit toggle to disable verification when using m_connectionhash_verify

	bool ShouldCheck(LocalUser* user) const
	{
		if (classes.empty())
			return true;

		std::shared_ptr<ConnectClass> klass = user->GetClass();
		if (!klass)
			return false;

		for (const auto& pattern : classes)
		{
			if (InspIRCd::Match(klass->name, pattern))
				return true;
		}
		return false;
	}

	std::string GenerateHash(const std::string& ip) const
	{
		if (!hasher || ip.empty())
			return "";

		std::string data = salt.empty() ? ip : (salt + ":" + ip);
		std::string digest = hasher->Generate(data);

		if (digest.length() < 11)
			return "";

		return digest.substr(0, 11);
	}

	bool VerifyIdentHash(LocalUser* user) const
	{
		const std::string ident = user->GetDisplayedUser();

		// Check format: w + 11 hex chars = 12 total
		if (ident.length() != 12 || ident.front() != 'w')
			return true; // Not a hashed ident, skip verification

		std::string expectedHash = GenerateHash(user->GetAddress());
		if (expectedHash.empty())
			return true;

		std::string expected = "w" + expectedHash;
		return expected == ident;
	}

	bool VerifyRealnameHash(LocalUser* user, const rapidjson::Document& doc) const
	{
		// Check if username matches pattern (e.g., "kiwi-user")
		const std::string ident = user->GetDisplayedUser();
		if (!usernamePattern.empty() && !InspIRCd::Match(ident, usernamePattern))
			return true; // Username doesn't match, skip verification

		// Check if hash key exists in JSON
		if (!doc.HasMember(hashKey.c_str()))
		{
			ServerInstance->Logs.Normal(MODNAME, "Realname JSON missing hash key '{}' for user {} ({})", hashKey, user->nick, user->GetAddress());
			return false;
		}

		const rapidjson::Value& field = doc[hashKey.c_str()];
		if (!field.IsString())
		{
			ServerInstance->Logs.Normal(MODNAME, "Realname JSON hash key '{}' is not a string for user {} ({})", hashKey, user->nick, user->GetAddress());
			return false;
		}

		const std::string jsonHash = field.GetString();
		std::string expectedHash = GenerateHash(user->GetAddress());

		ServerInstance->Logs.Normal(MODNAME, "Verify: user={} ip={} jsonHash={} expectedHash={} match={}",
			user->nick, user->GetAddress(), jsonHash, expectedHash, (jsonHash == expectedHash ? "YES" : "NO"));

		if (expectedHash.empty())
			return true;

		return jsonHash == expectedHash;
	}

public:
	ModuleGecosJSON()
		: Module(VF_VENDOR | VF_COMMON, "Parses JSON in GECOS, verifies identity hashes, and optionally strips fields.")
		, hasher(nullptr)
	{
	}

	void ReadConfig(ConfigStatus&) override
	{
		hasher = ServerInstance->Modules.FindDataService<HashProvider>("hash/sha256");

		const auto& tag = ServerInstance->Config->ConfValue("gecosjson");
		salt = tag->getString("salt");
		kickreason = tag->getString("reason", "Invalid identity verification");
		mode = tag->getString("mode", "off");
		usernamePattern = tag->getString("usernamepattern", "");
		hashKey = tag->getString("hashkey", "ih");
		// verifyhash: explicit toggle (default "yes" for backwards compat, set to "no" when using m_connectionhash_verify)
		verifyhash = tag->getBool("verifyhash", true);

		// Parse stripfields: comma-separated list or "*" for all
		stripFields.clear();
		std::string stripFieldsStr = tag->getString("stripfields", "");
		if (!stripFieldsStr.empty())
		{
			if (stripFieldsStr == "*")
			{
				// Will be handled specially - strip all fields
				stripFields.push_back("*");
			}
			else
			{
				irc::commasepstream fieldReader(stripFieldsStr);
				std::string field;
				while (fieldReader.GetToken(field))
				{
					// Trim whitespace
					size_t start = field.find_first_not_of(" \t");
					size_t end = field.find_last_not_of(" \t");
					if (start != std::string::npos && end != std::string::npos)
					{
						stripFields.push_back(field.substr(start, end - start + 1));
					}
				}
			}
		}

		classes.clear();
		irc::spacesepstream reader(tag->getString("classes"));
		std::string token;
		while (reader.GetToken(token))
			classes.push_back(token);

		ServerInstance->Logs.Debug(MODNAME, "Config: mode={} hashkey={} stripfields={} verifyhash={}",
			mode, hashKey, tag->getString("stripfields", ""), verifyhash ? "yes" : "no");
	}

	void OnUserConnect(LocalUser* user) override
	{
		if (!ShouldCheck(user))
			return;

		std::string realname = user->GetRealName();

		ServerInstance->Logs.Normal(MODNAME, "OnUserConnect: user={} ident={} realname={} mode={}",
			user->nick, user->GetDisplayedUser(), realname, mode);

		// Try to parse realname as JSON
		rapidjson::Document doc;
		bool isJson = false;
		if (!realname.empty() && !doc.Parse(realname.c_str()).HasParseError() && doc.IsObject())
			isJson = true;

		// Verify based on mode (only if verifyhash is enabled)
		bool verified = true;
		bool shouldEnforce = (mode != "off") && verifyhash;

		if (verifyhash && (mode == "ident" || mode == "both" || mode == "off") && !salt.empty())
		{
			verified = VerifyIdentHash(user);
			if (mode == "off")
				verified = true; // Don't actually fail in off mode
		}

		if (verifyhash && (mode == "realname" || mode == "both" || mode == "off") && !salt.empty() && isJson)
		{
			bool realnameVerified = VerifyRealnameHash(user, doc);
			if (mode != "off")
			{
				verified = verified && realnameVerified;
			}

			// Strip the hash field from the realname JSON after successful verification
			if (realnameVerified && doc.HasMember(hashKey.c_str()))
			{
				doc.RemoveMember(hashKey.c_str());
				rapidjson::StringBuffer buffer;
				rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
				doc.Accept(writer);
				user->ChangeRealName(buffer.GetString());
			}
		}
		else if (verifyhash && mode == "realname" && !salt.empty() && !isJson)
		{
			// Only fail if username matches the pattern (e.g., kiwi-user)
			const std::string ident = user->GetDisplayedUser();
			if (!usernamePattern.empty() && InspIRCd::Match(ident, usernamePattern))
			{
				ServerInstance->Logs.Normal(MODNAME, "Realname is not valid JSON for user {} with ident {}", user->nick, ident);
				verified = false;
			}
		}

		if (!verified && shouldEnforce)
		{
			ServerInstance->Logs.Normal(MODNAME, "Identity verification failed for {} ({})", user->nick, user->GetAddress());
			ServerInstance->Users.QuitUser(user, kickreason);
			return;
		}

		// Selectively strip fields from realname if configured
		if (!stripFields.empty() && isJson)
		{
			// Check if we should strip all fields
			bool stripAll = (stripFields.size() == 1 && stripFields[0] == "*");

			if (stripAll)
			{
				user->ChangeRealName("");
				ServerInstance->Logs.Debug(MODNAME, "Stripped all JSON fields from realname for user {}", user->nick);
			}
			else
			{
				bool stripped = false;
				for (const auto& field : stripFields)
				{
					if (doc.HasMember(field.c_str()))
					{
						doc.RemoveMember(field.c_str());
						stripped = true;
					}
				}

				if (!stripped)
					return;

				if (doc.ObjectEmpty())
				{
					user->ChangeRealName("");
				}
				else
				{
					rapidjson::StringBuffer buffer;
					rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
					doc.Accept(writer);
					user->ChangeRealName(buffer.GetString());
				}
			}
		}
	}
};

MODULE_INIT(ModuleGecosJSON)
