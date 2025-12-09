/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 * Trigger actions based on user metadata values.
 *
 * Configuration:
 *   <metadata_trigger key="geo/country-code" action="join" target="#lobby-$value" trigger="once">
 *   <metadata_trigger key="geo/country-code" value="US" action="join" target="#us-users" trigger="once">
 *   <metadata_trigger key="verified" value="true" action="mode" target="+V" trigger="always">
 *
 * Attributes:
 *   key     - metadata key to match (required)
 *   value   - specific value to match (optional, if omitted matches any non-empty value)
 *   action  - action to perform: join, mode, notice (required)
 *   target  - target for the action, $value is substituted with metadata value (required)
 *   trigger - when to trigger: once (default, only on connect), always (any metadata change)
 *   delay   - seconds to wait before triggering (optional, default 0)
 */

#include "inspircd.h"
#include "extension.h"
#include "modules/ircv3_metadata.h"

struct TriggerConfig
{
	std::string key;
	std::string value;      // empty = match any non-empty value
	std::string action;     // join, mode, notice
	std::string target;     // target with $value placeholder
	bool triggerOnce;       // true = only on connect, false = on any change
	unsigned int delay;     // seconds to delay

	std::string GetTarget(const std::string& metavalue) const
	{
		std::string result = target;
		std::string::size_type pos = result.find("$value");
		while (pos != std::string::npos)
		{
			result.replace(pos, 6, metavalue);
			pos = result.find("$value", pos + metavalue.length());
		}
		return result;
	}

	bool Matches(const std::string& metavalue) const
	{
		if (metavalue.empty())
			return false;
		if (value.empty())
			return true;  // match any non-empty
		return value == metavalue;
	}
};

// Pending trigger to execute after user connects
struct PendingTrigger
{
	std::string action;
	std::string target;
	unsigned int delay;
};

// Track which triggers have fired for a user (for trigger="once")
class FiredTriggersExt final
	: public SimpleExtItem<std::set<std::string>>
{
public:
	FiredTriggersExt(Module* mod)
		: SimpleExtItem<std::set<std::string>>(mod, "metadata-trigger-fired", ExtensionType::USER)
	{
	}

	bool HasFired(User* user, const std::string& triggerKey)
	{
		std::set<std::string>* fired = Get(user);
		return fired && fired->count(triggerKey) > 0;
	}

	void MarkFired(User* user, const std::string& triggerKey)
	{
		std::set<std::string>* fired = Get(user);
		if (!fired)
		{
			fired = new std::set<std::string>();
			Set(user, fired, false);
		}
		fired->insert(triggerKey);
	}
};

// Store pending triggers for users not yet fully connected
class PendingTriggersExt final
	: public SimpleExtItem<std::vector<PendingTrigger>>
{
public:
	PendingTriggersExt(Module* mod)
		: SimpleExtItem<std::vector<PendingTrigger>>(mod, "metadata-trigger-pending", ExtensionType::USER)
	{
	}

	void Add(User* user, const std::string& action, const std::string& target, unsigned int delay)
	{
		std::vector<PendingTrigger>* pending = Get(user);
		if (!pending)
		{
			pending = new std::vector<PendingTrigger>();
			Set(user, pending, false);
		}
		pending->push_back({action, target, delay});
	}

	std::vector<PendingTrigger>* GetAndClear(User* user)
	{
		return Get(user);
	}
};

// Timer for delayed triggers
class TriggerTimer final
	: public Timer
{
private:
	LocalUser* const user;
	const std::string action;
	const std::string target;

public:
	TriggerTimer(LocalUser* u, const std::string& act, const std::string& tgt, unsigned int delay)
		: Timer(delay, false)
		, user(u)
		, action(act)
		, target(tgt)
	{
		ServerInstance->Timers.AddTimer(this);
	}

	bool Tick() override
	{
		if (!user->IsFullyConnected())
			return false;

		ServerInstance->Logs.Debug("metadata_trigger", "Timer firing: action={} target={} user={}",
			action, target, user->nick);

		if (action == "join")
		{
			if (ServerInstance->Channels.IsChannel(target))
				Channel::JoinUser(user, target);
		}
		else if (action == "mode")
		{
			Modes::ChangeList changelist;
			if (target.length() >= 2 && (target[0] == '+' || target[0] == '-'))
			{
				bool adding = (target[0] == '+');
				for (size_t i = 1; i < target.length(); i++)
				{
					ModeHandler* mh = ServerInstance->Modes.FindMode(target[i], MODETYPE_USER);
					if (mh)
						changelist.push(mh, adding);
				}
				ServerInstance->Modes.Process(ServerInstance->FakeClient, NULL, user, changelist);
			}
		}
		else if (action == "notice")
		{
			user->WriteNotice(target);
		}

		return false;
	}
};

class ModuleMetadataTrigger final
	: public Module
	, public IRCv3::Metadata::EventListener
{
private:
	std::vector<TriggerConfig> triggers;
	FiredTriggersExt firedExt;
	PendingTriggersExt pendingExt;

	void ExecuteAction(LocalUser* user, const std::string& action, const std::string& target, unsigned int delay)
	{
		if (delay > 0)
		{
			new TriggerTimer(user, action, target, delay);
			return;
		}

		// Execute immediately
		if (action == "join")
		{
			if (ServerInstance->Channels.IsChannel(target))
				Channel::JoinUser(user, target);
		}
		else if (action == "mode")
		{
			Modes::ChangeList changelist;
			if (target.length() >= 2 && (target[0] == '+' || target[0] == '-'))
			{
				bool adding = (target[0] == '+');
				for (size_t i = 1; i < target.length(); i++)
				{
					ModeHandler* mh = ServerInstance->Modes.FindMode(target[i], MODETYPE_USER);
					if (mh)
						changelist.push(mh, adding);
				}
				ServerInstance->Modes.Process(ServerInstance->FakeClient, NULL, user, changelist);
			}
		}
		else if (action == "notice")
		{
			user->WriteNotice(target);
		}
	}

	void QueueOrExecuteTrigger(LocalUser* user, const TriggerConfig& trigger, const std::string& metavalue)
	{
		std::string triggerKey = trigger.key + ":" + trigger.value + ":" + trigger.action + ":" + trigger.target;

		// Check if already fired for trigger="once"
		if (trigger.triggerOnce && firedExt.HasFired(user, triggerKey))
			return;

		std::string realTarget = trigger.GetTarget(metavalue);

		ServerInstance->Logs.Debug(MODNAME, "Processing trigger: action={} target={} user={} key={} value={} connected={}",
			trigger.action, realTarget, user->nick, trigger.key, metavalue, user->IsFullyConnected() ? "yes" : "no");

		if (trigger.triggerOnce)
			firedExt.MarkFired(user, triggerKey);

		if (!user->IsFullyConnected())
		{
			// Queue for later execution
			ServerInstance->Logs.Debug(MODNAME, "Queuing trigger for later: user={} action={} target={}",
				user->nick, trigger.action, realTarget);
			pendingExt.Add(user, trigger.action, realTarget, trigger.delay);
			return;
		}

		ExecuteAction(user, trigger.action, realTarget, trigger.delay);
	}

	void CheckTriggersForUser(LocalUser* user, const std::string& key, const std::string& value)
	{
		for (const auto& trigger : triggers)
		{
			if (trigger.key != key)
				continue;

			if (trigger.Matches(value))
				QueueOrExecuteTrigger(user, trigger, value);
		}
	}

public:
	ModuleMetadataTrigger()
		: Module(VF_VENDOR, "Trigger actions based on user metadata values")
		, IRCv3::Metadata::EventListener(this)
		, firedExt(this)
		, pendingExt(this)
	{
	}

	void ReadConfig(ConfigStatus& status) override
	{
		std::vector<TriggerConfig> newtriggers;

		for (const auto& [_, tag] : ServerInstance->Config->ConfTags("metadata_trigger"))
		{
			TriggerConfig tc;
			tc.key = tag->getString("key");
			tc.value = tag->getString("value");
			tc.action = tag->getString("action");
			tc.target = tag->getString("target");
			tc.delay = static_cast<unsigned int>(tag->getDuration("delay", 0, 0, 300));

			std::string triggerStr = tag->getString("trigger", "once");
			tc.triggerOnce = (triggerStr != "always");

			if (tc.key.empty())
			{
				ServerInstance->Logs.Warning(MODNAME, "Ignoring metadata_trigger with empty key");
				continue;
			}
			if (tc.action.empty())
			{
				ServerInstance->Logs.Warning(MODNAME, "Ignoring metadata_trigger with empty action for key={}", tc.key);
				continue;
			}
			if (tc.action != "join" && tc.action != "mode" && tc.action != "notice")
			{
				ServerInstance->Logs.Warning(MODNAME, "Ignoring metadata_trigger with unknown action={} for key={}", tc.action, tc.key);
				continue;
			}
			if (tc.target.empty())
			{
				ServerInstance->Logs.Warning(MODNAME, "Ignoring metadata_trigger with empty target for key={}", tc.key);
				continue;
			}

			ServerInstance->Logs.Normal(MODNAME, "Loaded trigger: key={} value={} action={} target={} trigger={} delay={}",
				tc.key, tc.value.empty() ? "*" : tc.value, tc.action, tc.target, tc.triggerOnce ? "once" : "always", tc.delay);

			newtriggers.push_back(tc);
		}

		triggers.swap(newtriggers);
		ServerInstance->Logs.Normal(MODNAME, "Loaded {} metadata trigger(s)", triggers.size());
	}

	void OnMetadataChanged(User* setter, const IRCv3::Metadata::TargetInfo& target,
		const std::string& key, const std::string& value, bool removing) override
	{
		if (removing || target.ischannel || !target.user)
			return;

		LocalUser* localuser = IS_LOCAL(target.user);
		if (!localuser)
			return;

		ServerInstance->Logs.Debug(MODNAME, "OnMetadataChanged: user={} key={} value={}",
			localuser->nick, key, value);

		CheckTriggersForUser(localuser, key, value);
	}

	void Prioritize() override
	{
		ServerInstance->Modules.SetPriority(this, I_OnPostConnect, PRIORITY_LAST);
	}

	void OnPostConnect(User* user) override
	{
		LocalUser* localuser = IS_LOCAL(user);
		if (!localuser)
			return;

		ServerInstance->Logs.Debug(MODNAME, "OnPostConnect: user={}", localuser->nick);

		// Execute any pending triggers
		std::vector<PendingTrigger>* pending = pendingExt.GetAndClear(localuser);
		if (pending)
		{
			ServerInstance->Logs.Debug(MODNAME, "Executing {} pending triggers for user={}",
				pending->size(), localuser->nick);

			for (const auto& pt : *pending)
			{
				ExecuteAction(localuser, pt.action, pt.target, pt.delay);
			}
			pendingExt.Unset(localuser);
		}
	}
};

MODULE_INIT(ModuleMetadataTrigger)
