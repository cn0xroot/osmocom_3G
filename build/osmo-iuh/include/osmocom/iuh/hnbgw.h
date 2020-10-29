#pragma once

#include <osmocom/core/select.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/timer.h>
#include <osmocom/sigtran/sccp_sap.h>

#define DEBUG
#include <osmocom/core/logging.h>


enum {
	DMAIN,
	DHNBAP,
	DSUA,
	DRUA,
	DRANAP,
};


#define HNBGW_LOCAL_IP_DEFAULT "0.0.0.0"
#define HNBGW_IUCS_REMOTE_IP_DEFAULT "127.0.0.1"
#define HNBGW_IUPS_REMOTE_IP_DEFAULT "127.0.0.2"

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

struct hnb_gw;

enum hnbgw_cnlink_state {
	/* we have just been initialized or were disconnected */
	CNLINK_S_NULL,
	/* establishment of the SUA/SCCP link is pending */
	CNLINK_S_EST_PEND,
	/* establishment of the SUA/SCCP link was confirmed */
	CNLINK_S_EST_CONF,
	/* we have esnt the RANAP RESET and wait for the ACK */
	CNLINK_S_EST_RST_TX_WAIT_ACK,
	/* we have received the RANAP RESET ACK and are active */
	CNLINK_S_EST_ACTIVE,
};

struct hnbgw_cnlink {
	struct llist_head list;
	enum hnbgw_cnlink_state state;
	struct hnb_gw *gw;
	/* are we a PS connection (1) or CS (0) */
	int is_ps;
	/* timer for re-transmitting the RANAP Reset */
	struct osmo_timer_list T_RafC;
	/* reference to the SCCP User SAP by which we communicate */
	struct osmo_sccp_user *sua_user;
	struct osmo_sccp_link *sua_link;
	struct osmo_sccp_addr local_addr;
	struct osmo_sccp_addr remote_addr;
	uint32_t next_conn_id;

	/* linked list of hnbgw_context_map */
	struct llist_head map_list;
};

struct hnb_context {
	/*! Entry in HNB-global list of HNB */
	struct llist_head list;
	/*! HNB-GW we are part of */
	struct hnb_gw *gw;
	/*! SCTP socket + write queue for Iuh to this specific HNB */
	struct osmo_stream_srv *conn;
	/*! copied from HNB-Identity-Info IE */
	char identity_info[256];
	/*! copied from Cell Identity IE */
	struct umts_cell_id id;

	/*! SCTP stream ID for HNBAP */
	uint16_t hnbap_stream;
	/*! SCTP stream ID for RUA */
	uint16_t rua_stream;

	/* linked list of hnbgw_context_map */
	struct llist_head map_list;
};

struct ue_context {
	/*! Entry in the HNB-global list of UE */
	struct llist_head list;
	/*! Unique Context ID for this UE */
	uint32_t context_id;
	char imsi[16+1];
	uint32_t tmsi;
	/*! UE is serviced via this HNB */
	struct hnb_context *hnb;
};

struct hnb_gw {
	struct {
		const char *iuh_local_ip;
		/*! SCTP port for Iuh listening */
		uint16_t iuh_local_port;
		/*! The UDP port where we receive multiplexed CS user
		 * plane traffic from HNBs */
		uint16_t iuh_cs_mux_port;
		const char *iucs_remote_ip;
		uint16_t iucs_remote_port;
		const char *iups_remote_ip;
		uint16_t iups_remote_port;
		uint16_t rnc_id;
		bool hnbap_allow_tmsi;
	} config;
	/*! SCTP listen socket for incoming connections */
	struct osmo_stream_srv_link *iuh;
	/* list of struct hnb_context */
	struct llist_head hnb_list;
	/* list of struct ue_context */
	struct llist_head ue_list;
	/* list of struct hnbgw_cnlink */
	struct llist_head cn_list;
	/* next availble UE Context ID */
	uint32_t next_ue_ctx_id;

	/* currently active CN links for CS and PS */
	struct hnbgw_cnlink *cnlink_cs;
	struct hnbgw_cnlink *cnlink_ps;
};

extern void *talloc_asn1_ctx;

struct ue_context *ue_context_by_id(struct hnb_gw *gw, uint32_t id);
struct ue_context *ue_context_by_imsi(struct hnb_gw *gw, const char *imsi);
struct ue_context *ue_context_by_tmsi(struct hnb_gw *gw, uint32_t tmsi);
struct ue_context *ue_context_alloc(struct hnb_context *hnb, const char *imsi,
				    uint32_t tmsi);
void ue_context_free(struct ue_context *ue);

struct hnb_context *hnb_context_alloc(struct hnb_gw *gw, struct osmo_stream_srv_link *link, int new_fd);
void hnb_context_release(struct hnb_context *ctx);

void hnbgw_vty_init(struct hnb_gw *gw, void *tall_ctx);
int hnbgw_vty_go_parent(struct vty *vty);
