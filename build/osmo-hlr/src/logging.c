#include <osmocom/core/utils.h>
#include "logging.h"

const struct log_info_cat hlr_log_info_cat[] = {
	[DMAIN] = {
		.name = "DMAIN",
		.description = "Main Program",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DDB] = {
		.name = "DDB",
		.description = "Database Layer",
		.color = "\033[1;31m",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DAUC] = {
		.name = "DAUC",
		.description = "Authentication Center",
		.color = "\033[1;33m",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

const struct log_info hlr_log_info = {
	.cat = hlr_log_info_cat,
	.num_cat = ARRAY_SIZE(hlr_log_info_cat),
};
