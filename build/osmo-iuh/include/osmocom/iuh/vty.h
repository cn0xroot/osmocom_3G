#pragma once

#include <osmocom/vty/vty.h>

enum osmo_iuh_vty_node {
	HNBGW_NODE = _LAST_OSMOVTY_NODE + 1,
	IUH_NODE,
	IUCS_NODE,
	IUPS_NODE,
};

