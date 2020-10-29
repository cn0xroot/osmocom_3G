#ifndef OPENBSC_LAPD_H
#define OPENBSC_LAPD_H

#include <stdint.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/lapd_core.h>

struct lapd_profile {
	uint8_t k[64];
	int n200;
	int n201;
	int n202;
	int t200_sec, t200_usec;
	int t201_sec, t201_usec;
	int t202_sec, t202_usec;
	int t203_sec, t203_usec;
	int short_address;
};

/* predefined lapd profiles (see lapd.c for definition) */
extern const struct lapd_profile lapd_profile_isdn;
extern const struct lapd_profile lapd_profile_abis;
extern const struct lapd_profile lapd_profile_abis_ericsson;
extern const struct lapd_profile lapd_profile_sat;

struct lapd_instance {
	struct llist_head list;		/* list of LAPD instances */
	int network_side;

	void (*transmit_cb)(struct msgb *msg, void *cbdata);
	void *transmit_cbdata;
	void (*receive_cb)(struct osmo_dlsap_prim *odp, uint8_t tei,
		uint8_t sapi, void *rx_cbdata);
	void *receive_cbdata;

	struct lapd_profile profile; /* must be a copy */

	struct llist_head tei_list;	/* list of TEI in this LAPD instance */
	int pcap_fd;			/* PCAP file descriptor */
};

enum lapd_recv_errors {
	LAPD_ERR_NONE = 0,
	LAPD_ERR_BAD_LEN,
	LAPD_ERR_BAD_ADDR,
	LAPD_ERR_UNKNOWN_S_CMD,
	LAPD_ERR_UNKNOWN_U_CMD,
	LAPD_ERR_UNKNOWN_TEI,
	LAPD_ERR_BAD_CMD,
	LAPD_ERR_NO_MEM,
	__LAPD_ERR_MAX
};

struct lapd_tei *lapd_tei_alloc(struct lapd_instance *li, uint8_t tei);

int lapd_receive(struct lapd_instance *li, struct msgb *msg, int *error);

void lapd_transmit(struct lapd_instance *li, uint8_t tei, uint8_t sapi,
		   struct msgb *msg);

struct lapd_instance *lapd_instance_alloc(int network_side,
	void (*tx_cb)(struct msgb *msg, void *cbdata), void *tx_cbdata,
	void (*rx_cb)(struct osmo_dlsap_prim *odp, uint8_t tei, uint8_t sapi, 
			void *rx_cbdata), void *rx_cbdata,
	const struct lapd_profile *profile);

/* In rare cases (e.g. Ericsson's lapd dialect), it may be necessary to
 * exchange the lapd profile on the fly. lapd_instance_set_profile()
 * allwos to set the lapd profile on a lapd instance danymically to
 * one of the lapd profiles define above. */
void lapd_instance_set_profile(struct lapd_instance *li,
			       const struct lapd_profile *profile);

void lapd_instance_free(struct lapd_instance *li);

/* Start a (user-side) SAP for the specified TEI/SAPI on the LAPD instance */
int lapd_sap_start(struct lapd_instance *li, uint8_t tei, uint8_t sapi);

/* Stop a (user-side) SAP for the specified TEI/SAPI on the LAPD instance */
int lapd_sap_stop(struct lapd_instance *li, uint8_t tei, uint8_t sapi);

#endif /* OPENBSC_LAPD_H */
