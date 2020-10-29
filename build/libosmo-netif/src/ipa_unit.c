#include <osmocom/core/talloc.h>
#include <osmocom/core/linuxlist.h>

#include <stdint.h>
#include <string.h>

struct osmo_ipa_unit {
	struct llist_head head;

	uint16_t	site_id;
	uint16_t	bts_id;
	uint16_t	trx_id;
	char		*name;
	char		*hwvers;
	char		*swvers;
	uint8_t		mac_addr[6];
	char		*location1;
	char		*location2;
	char		*serno;

	uint8_t		data[0];
};

struct osmo_ipa_unit *osmo_ipa_unit_alloc(size_t datalen)
{
	struct osmo_ipa_unit *unit;

	unit = talloc_zero_size(NULL, sizeof(struct osmo_ipa_unit) + datalen);
	if (unit == NULL)
		return NULL;

	unit->name = talloc_strdup(unit, "");
	unit->hwvers = talloc_strdup(unit, "");
	unit->swvers = talloc_strdup(unit, "");
	unit->location1 = talloc_strdup(unit, "");
	unit->location2 = talloc_strdup(unit, "");
	unit->serno = talloc_strdup(unit, "");

	return unit;
}

void osmo_ipa_unit_free(struct osmo_ipa_unit *unit)
{
	if (unit->name)
		free(unit->name);
	if (unit->hwvers)
		free(unit->hwvers);
	if (unit->swvers)
		free(unit->swvers);
	if (unit->location1)
		free(unit->location1);
	if (unit->location2)
		free(unit->location2);
	if (unit->serno)
		free(unit->serno);

	talloc_free(unit);
}

void *osmo_ipa_unit_get_data(struct osmo_ipa_unit *unit)
{
	return unit->data;
}

void osmo_ipa_unit_set_site_id(struct osmo_ipa_unit *unit, uint16_t site_id)
{
	unit->site_id = site_id;
}

void osmo_ipa_unit_set_bts_id(struct osmo_ipa_unit *unit, uint16_t bts_id)
{
	unit->bts_id = bts_id;
}

void osmo_ipa_unit_set_trx_id(struct osmo_ipa_unit *unit, uint16_t trx_id)
{
	unit->trx_id = trx_id;
}

void osmo_ipa_unit_set_unit_name(struct osmo_ipa_unit *unit, const char *name)
{
	if (unit->name)
		free(unit->name);

	unit->name = talloc_strdup(unit, name);
}

void osmo_ipa_unit_set_unit_hwvers(struct osmo_ipa_unit *unit, const char *vers)
{
	if (unit->hwvers)
		free(unit->hwvers);

	unit->hwvers = talloc_strdup(unit, vers);
}

void osmo_ipa_unit_set_unit_swvers(struct osmo_ipa_unit *unit, const char *vers)
{
	if (unit->swvers)
		free(unit->swvers);

	unit->swvers = talloc_strdup(unit, vers);
}

void osmo_ipa_unit_set_unit_mac_addr(struct osmo_ipa_unit *unit, uint8_t *addr)
{
	memcpy(unit->mac_addr, addr, sizeof(unit->mac_addr));
}

void osmo_ipa_unit_set_unit_location1(struct osmo_ipa_unit *unit, const char *loc)
{
	if (unit->location1)
		free(unit->location1);

	unit->location1 = talloc_strdup(unit, loc);
}

void osmo_ipa_unit_set_unit_location2(struct osmo_ipa_unit *unit, const char *loc)
{
	if (unit->location2)
		free(unit->location2);

	unit->location2 = talloc_strdup(unit, loc);
}

void osmo_ipa_unit_set_unit_serno(struct osmo_ipa_unit *unit, const char *serno)
{
	unit->serno = talloc_strdup(unit, serno);
}

uint16_t osmo_ipa_unit_get_site_id(struct osmo_ipa_unit *unit)
{
	return unit->site_id;
}

uint16_t osmo_ipa_unit_get_bts_id(struct osmo_ipa_unit *unit)
{
	return unit->bts_id;
}

uint16_t osmo_ipa_unit_get_trx_id(struct osmo_ipa_unit *unit)
{
	return unit->trx_id;
}

const char *osmo_ipa_unit_get_unit_name(struct osmo_ipa_unit *unit)
{
	return unit->name;
}

const char *osmo_ipa_unit_get_unit_hwvers(struct osmo_ipa_unit *unit)
{
	return unit->hwvers;
}

const char *osmo_ipa_unit_get_unit_swvers(struct osmo_ipa_unit *unit)
{
	return unit->swvers;
}

uint8_t *osmo_ipa_unit_get_unit_mac_addr(struct osmo_ipa_unit *unit)
{
	return unit->mac_addr;
}

const char *osmo_ipa_unit_get_unit_location1(struct osmo_ipa_unit *unit)
{
	return unit->location1;
}

const char *osmo_ipa_unit_get_unit_location2(struct osmo_ipa_unit *unit)
{
	return unit->location2;
}

const char *osmo_ipa_unit_get_unit_serno(struct osmo_ipa_unit *unit)
{
	return unit->serno;
}

struct osmo_ipa_unit *
osmo_ipa_unit_find(struct llist_head *list, uint16_t site_id, uint16_t bts_id)
{
	struct osmo_ipa_unit *unit;

	llist_for_each_entry(unit, list, head) {
		if (unit->site_id == site_id &&
		    unit->bts_id == bts_id)
			return unit;
	}
	return NULL;
}

void osmo_ipa_unit_add(struct llist_head *list, struct osmo_ipa_unit *unit)
{
	llist_add(&unit->head, list);
}

int osmo_ipa_unit_snprintf(char *buf, size_t size, struct osmo_ipa_unit *unit)
{
	return snprintf(buf, size, "%u/%u/%u",
			unit->site_id, unit->bts_id, unit->trx_id);
}

int osmo_ipa_unit_snprintf_mac_addr(char *buf, size_t size,
				    struct osmo_ipa_unit *unit)
{
	return snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x",
			unit->mac_addr[0], unit->mac_addr[1],
			unit->mac_addr[2], unit->mac_addr[3],
			unit->mac_addr[4], unit->mac_addr[5]);
}

int osmo_ipa_unit_snprintf_name(char *buf, size_t size,
				struct osmo_ipa_unit *unit)
{
	return snprintf(buf, size, "%s-%02x-%02x-%02x-%02x-%02x-%02x",
			unit->name,
			unit->mac_addr[0], unit->mac_addr[1],
			unit->mac_addr[2], unit->mac_addr[3],
			unit->mac_addr[4], unit->mac_addr[5]);
}

int osmo_ipa_unit_snprintf_loc1(char *buf, size_t size,
				struct osmo_ipa_unit *unit)
{
	return snprintf(buf, size, "%s", unit->location1);
}

int osmo_ipa_unit_snprintf_loc2(char *buf, size_t size,
				struct osmo_ipa_unit *unit)
{
	return snprintf(buf, size, "%s", unit->location2);
}

int osmo_ipa_unit_snprintf_hwvers(char *buf, size_t size,
				  struct osmo_ipa_unit *unit)
{
	return snprintf(buf, size, "%s", unit->hwvers);
}

int osmo_ipa_unit_snprintf_swvers(char *buf, size_t size,
				  struct osmo_ipa_unit *unit)
{
	return snprintf(buf, size, "%s", unit->hwvers);
}

int osmo_ipa_unit_snprintf_serno(char *buf, size_t size,
				 struct osmo_ipa_unit *unit)
{
	return snprintf(buf, size, "%s", unit->serno);
}
