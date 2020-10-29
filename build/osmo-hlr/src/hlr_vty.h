/* OsmoHLR VTY implementation */

/* (C) 2016 sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <nhofmeyr@sysmocom.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#pragma once

#include <osmocom/core/logging.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>
#include "hlr.h"

enum hlr_vty_node {
	HLR_NODE = _LAST_OSMOVTY_NODE + 1,
	GSUP_NODE,
};

int hlr_vty_is_config_node(struct vty *vty, int node);
int hlr_vty_go_parent(struct vty *vty);
void hlr_vty_init(struct hlr *hlr, const struct log_info *cat);
