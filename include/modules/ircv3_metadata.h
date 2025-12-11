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


#pragma once

#include "event.h"

namespace IRCv3
{
namespace Metadata
{
	enum TargetMask
	{
		TARGET_NONE    = 0,
		TARGET_USER    = 1 << 0,
		TARGET_CHANNEL = 1 << 1,
		TARGET_ALL     = TARGET_USER | TARGET_CHANNEL
	};

	struct TargetInfo
	{
		std::string name;
		User* user = NULL;
		Channel* chan = NULL;
		bool ischannel = false;

		TargetInfo() = default;

		explicit TargetInfo(User* u)
			: name(u ? u->nick : std::string())
			, user(u)
		{
		}

		explicit TargetInfo(Channel* c)
			: name(c ? c->name : std::string())
			, chan(c)
			, ischannel(true)
		{
		}
	};

	struct KeySpec
	{
		std::string name;
		unsigned int targets = TARGET_ALL;
		std::string visibility = "*";
		bool operonly = false;
		bool servicesonly = false;
		std::string setpriv;
		std::string viewpriv;
	};

class EventListener
	: public Events::ModuleEventListener
{
 public:
	EventListener(Module* mod, unsigned int eventprio = DefaultPriority)
		: ModuleEventListener(mod, "event/ircv3-metadata", eventprio)
	{
	}

		virtual ModResult OnPreMetadataSet(LocalUser* user, const TargetInfo& target, const std::string& key, std::string& value, bool removing)
		{
			return MOD_RES_PASSTHRU;
		}

		virtual void OnMetadataChanged(User* setter, const TargetInfo& target, const std::string& key, const std::string& value, bool removing)
		{
		}
	};

	class APIBase
		: public DataProvider
	{
	 public:
		APIBase(Module* mod)
			: DataProvider(mod, "ircv3metadata")
		{
		}

		/** Register or override the definition of a metadata key. */
		virtual bool RegisterKey(Module* owner, const KeySpec& spec) = 0;

		/** Remove all keys registered by the specified module. */
		virtual void UnregisterKeys(Module* owner) = 0;

		/** Set a metadata key on a user.
		 * @param user The user to set metadata on.
		 * @param key The metadata key name.
		 * @param value The value to set.
		 * @return True if the key was set successfully.
		 */
		virtual bool SetKey(User* user, const std::string& key, const std::string& value) = 0;

		/** Set a metadata key on a channel.
		 * @param chan The channel to set metadata on.
		 * @param key The metadata key name.
		 * @param value The value to set.
		 * @return True if the key was set successfully.
		 */
		virtual bool SetKey(Channel* chan, const std::string& key, const std::string& value) = 0;

		/** Unset a metadata key from a user.
		 * @param user The user to unset metadata from.
		 * @param key The metadata key name.
		 * @return True if the key was unset successfully.
		 */
		virtual bool UnsetKey(User* user, const std::string& key) = 0;

		/** Unset a metadata key from a channel.
		 * @param chan The channel to unset metadata from.
		 * @param key The metadata key name.
		 * @return True if the key was unset successfully.
		 */
		virtual bool UnsetKey(Channel* chan, const std::string& key) = 0;

		/** Get a metadata key from a user.
		 * @param user The user to get metadata from.
		 * @param key The metadata key name.
		 * @return The value of the key, or empty string if not set.
		 */
		virtual std::string GetKey(User* user, const std::string& key) const = 0;

		/** Get a metadata key from a channel.
		 * @param chan The channel to get metadata from.
		 * @param key The metadata key name.
		 * @return The value of the key, or empty string if not set.
		 */
		virtual std::string GetKey(Channel* chan, const std::string& key) const = 0;
	};

class API final
		: public dynamic_reference<APIBase>
	{
	 public:
		API(Module* mod)
			: dynamic_reference<APIBase>(mod, "ircv3metadata")
		{
		}
	};
}
}
