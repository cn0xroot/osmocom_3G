#pragma once

#include <osmocom/core/select.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/write_queue.h>

#define DEBUG
#include <osmocom/core/logging.h>

enum {
	DMAIN,
	DHNBAP,
};


/* 25.467 Section 7.1 */
#define IUH_DEFAULT_SCTP_PORT	29169
#define RNA_DEFAULT_SCTP_PORT	25471

#define IUH_PPI_RUA		19
#define IUH_PPI_HNBAP		20
#define IUH_PPI_SABP		31
#define IUH_PPI_RNA		42
#define IUH_PPI_PUA		55

#define IUH_MSGB_SIZE	2048

struct umts_cell_id {
	uint16_t mcc;	/*!< Mobile Country Code */
	uint16_t mnc;	/*!< Mobile Network Code */
	uint16_t lac;	/*!< Locaton Area Code */
	uint16_t rac;	/*!< Routing Area Code */
	uint16_t sac;	/*!< Service Area Code */
	uint32_t cid;	/*!< Cell ID */
};

struct ue_context {
	/*! Entry in the HNB-global list of UE */
	struct llist_head list;
	/*! Unique Context ID for this UE */
	uint32_t context_id;
	char imsi[16+1];
};

struct hnbtest_chan {
	int is_ps;
	uint32_t conn_id;
	char *imsi;
};

struct hnb_test {
	const char *gw_addr;
	uint16_t gw_port;
	/*! SCTP listen socket for incoming connections */
	struct osmo_fd conn_fd;

	/*! SCTP socket + write queue for Iuh to this specific HNB */
	struct osmo_wqueue wqueue;
	/*! copied from HNB-Identity-Info IE */
	char identity_info[256];
	/*! copied from Cell Identity IE */
	struct umts_cell_id id;

	/*! SCTP stream ID for HNBAP */
	uint16_t hnbap_stream;
	/*! SCTP stream ID for RUA */
	uint16_t rua_stream;

	uint16_t rnc_id;

	uint32_t ctx_id;

	int ues;

	struct {
		struct hnbtest_chan *chan;
	} cs;
};

extern struct hnb_test g_hnb_test;
