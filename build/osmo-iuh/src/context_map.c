/* Mapper between RUA ContextID (24 bit, per HNB) and the SUA/SCCP
 * Connection ID (32bit, per signalling link) */

/* (C) 2015 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
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

/* an expired mapping is destroyed  after 1..2 * EXPIRY_TIMER_SECS */
#define EXPIRY_TIMER_SECS	23

#include <osmocom/core/timer.h>

#include <osmocom/iuh/hnbgw.h>
#include <osmocom/iuh/context_map.h>

/* is a given SCCP USER SAP Connection ID in use for a given CN link? */
static int cn_id_in_use(struct hnbgw_cnlink *cn, uint32_t id)
{
	struct hnbgw_context_map *map;

	llist_for_each_entry(map, &cn->map_list, cn_list) {
		if (map->scu_conn_id == id)
			return 1;
	}
	return 0;
}

/* try to allocate a new SCCP User SAP Connection ID */
static int alloc_cn_conn_id(struct hnbgw_cnlink *cn, uint32_t *id_out)
{
	uint32_t i;
	uint32_t id;

	for (i = 0; i < 0xffffffff; i++) {
		id = cn->next_conn_id++;
		if (!cn_id_in_use(cn, id)) {
			*id_out = id;
			return 1;
		}
	}
	return -1;
}

/* Map from a HNB + ContextID to the SCCP-side Connection ID */
struct hnbgw_context_map *
context_map_alloc_by_hnb(struct hnb_context *hnb, uint32_t rua_ctx_id,
			 struct hnbgw_cnlink *cn_if_new)
{
	struct hnbgw_context_map *map;
	uint32_t new_scu_conn_id;

	llist_for_each_entry(map, &hnb->map_list, hnb_list) {
		if (map->state != MAP_S_ACTIVE)
			continue;
		if (map->cn_link != cn_if_new) {
			continue;
		}
		if (map->rua_ctx_id == rua_ctx_id) {
			return map;
		}
	}

	if (alloc_cn_conn_id(cn_if_new, &new_scu_conn_id) < 0) {
		LOGP(DMAIN, LOGL_ERROR, "Unable to allocate CN connection ID\n");
		return NULL;
	}

	LOGP(DMAIN, LOGL_INFO, "Creating new Mapping RUA CTX %p/%u <-> SCU Conn ID %p/%u\n",
		hnb, rua_ctx_id, cn_if_new, new_scu_conn_id);

	/* alloate a new map entry */
	map = talloc_zero(hnb, struct hnbgw_context_map);
	map->state = MAP_S_NULL;
	map->cn_link = cn_if_new;
	map->hnb_ctx = hnb;
	map->rua_ctx_id = rua_ctx_id;
	map->scu_conn_id = new_scu_conn_id;

	/* put it into both lists */
	llist_add_tail(&map->hnb_list, &hnb->map_list);
	llist_add_tail(&map->cn_list, &cn_if_new->map_list);
	map->state = MAP_S_ACTIVE;

	return map;
}

/* Map from a CN + Connection ID to HNB + Context ID */
struct hnbgw_context_map *
context_map_by_cn(struct hnbgw_cnlink *cn, uint32_t scu_conn_id)
{
	struct hnbgw_context_map *map;

	llist_for_each_entry(map, &cn->map_list, cn_list) {
		if (map->state != MAP_S_ACTIVE)
			continue;
		if (map->scu_conn_id == scu_conn_id) {
			return map;
		}
	}
	/* we don't allocate new mappings in the CN->HNB
	 * direction, as the RUA=SCCP=SUA connections are always
	 * established from HNB towards CN. */
	LOGP(DMAIN, LOGL_NOTICE, "Unable to resolve map for CN "
		"connection ID %p/%u\n", cn, scu_conn_id);
	return NULL;
}

void context_map_deactivate(struct hnbgw_context_map *map)
{
	/* set the state to reserved. We still show up in the list and
	 * avoid re-allocation of the context-id until we are cleaned up
	 * by the context_map garbage collector timer */

	if (map->state != MAP_S_RESERVED2)
		map->state = MAP_S_RESERVED1;
}

static struct osmo_timer_list context_map_tmr;

static void context_map_tmr_cb(void *data)
{
	struct hnb_gw *gw = data;
	struct hnbgw_cnlink *cn;

	DEBUGP(DMAIN, "Running context mapper garbage collection\n");
	/* iterate over list of core network (links) */
	llist_for_each_entry(cn, &gw->cn_list, list) {
		struct hnbgw_context_map *map;

		llist_for_each_entry(map, &cn->map_list, cn_list) {
			switch (map->state) {
			case MAP_S_RESERVED1:
				/* first time we see this reserved
				 * entry: mark it for stage 2 */
				map->state = MAP_S_RESERVED2;
				break;
			case MAP_S_RESERVED2:
				/* first time we see this reserved
				 * entry: remove it */
				map->state = MAP_S_NULL;
				llist_del(&map->cn_list);
				llist_del(&map->hnb_list);
				talloc_free(map);
				break;
			default:
				break;
			}
		}
	}
	/* re-schedule this timer */
	osmo_timer_schedule(&context_map_tmr, EXPIRY_TIMER_SECS, 0);
}

int context_map_init(struct hnb_gw *gw)
{
	context_map_tmr.cb = context_map_tmr_cb;
	context_map_tmr.data = gw;
	osmo_timer_schedule(&context_map_tmr, EXPIRY_TIMER_SECS, 0);
}
