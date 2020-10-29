#ifndef _ABIS_IPA_SERVER_H_
#define _ABIS_IPA_SERVER_H_

void osmo_abis_ipa_srv_set_oml_addr(struct osmo_chan *c, const char *addr);
void osmo_abis_ipa_srv_set_oml_port(struct osmo_chan *c, uint16_t port);

void osmo_abis_ipa_srv_set_rsl_addr(struct osmo_chan *c, const char *addr);
void osmo_abis_ipa_srv_set_rsl_port(struct osmo_chan *c, uint16_t port);

void osmo_abis_ipa_srv_set_cb_signalmsg(struct osmo_chan *c, void (*signal_msg)(struct msgb *msg, int type));

int osmo_abis_ipa_unit_add(struct osmo_chan *c, uint16_t site_id, uint16_t bts_id);

#endif
