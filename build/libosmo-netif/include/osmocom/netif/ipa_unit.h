#ifndef _IPA_UNIT_H_
#define _IPA_UNIT_H_

struct osmo_ipa_unit;

struct osmo_ipa_unit *osmo_ipa_unit_alloc(size_t datalen);
void osmo_ipa_unit_free(struct osmo_ipa_unit *unit);

void *osmo_ipa_unit_get_data(struct osmo_ipa_unit *unit);

void osmo_ipa_unit_set_site_id(struct osmo_ipa_unit *unit, uint16_t site_id);
void osmo_ipa_unit_set_bts_id(struct osmo_ipa_unit *unit, uint16_t bts_id);
void osmo_ipa_unit_set_trx_id(struct osmo_ipa_unit *unit, uint16_t trx_id);
void osmo_ipa_unit_set_unit_name(struct osmo_ipa_unit *unit, const char *name);
void osmo_ipa_unit_set_unit_hwvers(struct osmo_ipa_unit *unit, const char *vers);
void osmo_ipa_unit_set_unit_swvers(struct osmo_ipa_unit *unit, const char *vers);
void osmo_ipa_unit_set_unit_mac_addr(struct osmo_ipa_unit *unit, uint8_t *addr);
void osmo_ipa_unit_set_unit_loc1(struct osmo_ipa_unit *unit, const char *loc);
void osmo_ipa_unit_set_unit_loc2(struct osmo_ipa_unit *unit, const char *loc);
void osmo_ipa_unit_set_unit_serno(struct osmo_ipa_unit *unit, const char *serno);

uint16_t osmo_ipa_unit_get_site_id(struct osmo_ipa_unit *unit);
uint16_t osmo_ipa_unit_get_bts_id(struct osmo_ipa_unit *unit);
uint16_t osmo_ipa_unit_get_trx_id(struct osmo_ipa_unit *unit);
const char *osmo_ipa_unit_get_unit_name(struct osmo_ipa_unit *unit);
const char *osmo_ipa_unit_get_unit_hwvers(struct osmo_ipa_unit *unit);
const char *osmo_ipa_unit_get_unit_swvers(struct osmo_ipa_unit *unit);
uint8_t *osmo_ipa_unit_get_unit_mac_addr(struct osmo_ipa_unit *unit);
const char *osmo_ipa_unit_get_unit_loc1(struct osmo_ipa_unit *unit);
const char *osmo_ipa_unit_get_unit_loc2(struct osmo_ipa_unit *unit);
const char *osmo_ipa_unit_get_unit_serno(struct osmo_ipa_unit *unit);

int osmo_ipa_unit_snprintf(char *buf, size_t size, struct osmo_ipa_unit *unit);
int osmo_ipa_unit_snprintf_mac_addr(char *buf, size_t size, struct osmo_ipa_unit *unit);
int osmo_ipa_unit_snprintf_name(char *buf, size_t size, struct osmo_ipa_unit *unit);
int osmo_ipa_unit_snprintf_loc1(char *buf, size_t size, struct osmo_ipa_unit *unit);
int osmo_ipa_unit_snprintf_loc2(char *buf, size_t size, struct osmo_ipa_unit *unit);
int osmo_ipa_unit_snprintf_hwvers(char *buf, size_t size, struct osmo_ipa_unit *unit);
int osmo_ipa_unit_snprintf_swvers(char *buf, size_t size, struct osmo_ipa_unit *unit);
int osmo_ipa_unit_snprintf_swvers(char *buf, size_t size, struct osmo_ipa_unit *unit);
int osmo_ipa_unit_snprintf_serno(char *buf, size_t size, struct osmo_ipa_unit *unit);

struct osmo_ipa_unit *osmo_ipa_unit_find(struct llist_head *list, uint16_t site_id, uint16_t bts_id);
void osmo_ipa_unit_add(struct llist_head *list, struct osmo_ipa_unit *unit);

#endif	/* _IPA_UNIT_H_ */
