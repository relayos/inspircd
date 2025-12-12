/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2024 Allen Day
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
#include "modules/geolocation.h"
#include "modules/ircv3_metadata.h"

class ModuleGeoMetadata final
	: public Module
{
private:
	Geolocation::API geoapi;
	IRCv3::Metadata::API metaapi;

	void UpdateGeoMetadata(User* user)
	{
		// No-op: geo metadata is sourced from WEBIRC; skip server-side geolocation.
	}

public:
	ModuleGeoMetadata()
		: Module(VF_VENDOR | VF_OPTCOMMON, "Sets IRCv3 metadata keys with geolocation data for users.")
		, geoapi(this)
		, metaapi(this)
	{
	}

	void init() override
	{
		// Disable server-side geo metadata population; rely on WEBIRC-provided tags.
	}

	void OnChangeRemoteAddress(LocalUser* user) override
	{
		UpdateGeoMetadata(user);
	}

	ModResult OnUserRegister(LocalUser* user) override
	{
		UpdateGeoMetadata(user);
		return MOD_RES_PASSTHRU;
	}

	void OnUserDisconnect(LocalUser* user) override
	{
		// No-op: nothing to clean up; WEBIRC handles metadata lifecycle.
	}
};

MODULE_INIT(ModuleGeoMetadata)
