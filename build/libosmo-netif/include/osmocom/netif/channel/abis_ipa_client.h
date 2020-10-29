#ifndef _OSMO_ABIS_IPA_CLIENT_H_
#define _OSMO_ABIS_IPA_CLIENT_H_

struct osmo_ipa_unit;

void osmo_abis_ipa_cli_set_oml_addr(struct osmo_chan *c, const char *addr);
void osmo_abis_ipa_cli_set_oml_port(struct osmo_chan *c, uint16_t port);
void osmo_abis_ipa_cli_set_rsl_addr(struct osmo_chan *c, const char *addr);
void osmo_abis_ipa_cli_set_rsl_port(struct osmo_chan *c, uint16_t port);
void osmo_abis_ipa_cli_set_unit(struct osmo_chan *c, struct osmo_ipa_unit *unit);
void osmo_abis_ipa_cli_set_cb_signalmsg(struct osmo_chan *c, void (*signal_msg)(struct msgb *msg, int type));

#endif /* _OSMO_ABIS_IPA_CLIENT_H_ */
