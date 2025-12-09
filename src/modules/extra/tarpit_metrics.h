#pragma once

#include "serviceprovider.h"

struct TarpitMetrics final
{
	unsigned long long total_processed = 0;
	unsigned long long total_delayed = 0;
	unsigned long long total_dropped = 0;
	unsigned long long total_delay = 0;

	unsigned long long window_processed = 0;
	unsigned long long window_delayed = 0;
	unsigned long long window_dropped = 0;
	unsigned long long window_delay = 0;

	unsigned int current_level = 0;
};

/** Service to expose tarpit metrics to other modules (e.g., http exporters). */
class TarpitMetricsProvider
	: public DataProvider
{
public:
	TarpitMetricsProvider(Module* mod)
		: DataProvider(mod, "tarpit_metrics")
	{
	}

	/** Populate tarpit metrics. @param window Seconds to look back (0 = all time). */
	virtual bool GetStats(TarpitMetrics& out, unsigned long window = 0) = 0;
};
