#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <osmocom/ranap/RANAP_Cause.h>
#include <osmocom/ranap/RANAP_CN-DomainIndicator.h>
#include <osmocom/ranap/RANAP_GlobalRNC-ID.h>
#include <osmocom/ranap/RANAP_ChosenIntegrityProtectionAlgorithm.h>
#include <osmocom/ranap/RANAP_ChosenEncryptionAlgorithm.h>

/*! \brief generate RANAP DIRECT TRANSFER message */
struct msgb *ranap_new_msg_dt(uint8_t sapi, const uint8_t *nas, unsigned int nas_len);

/*! \brief generate RANAP SECURITY MODE COMMAND message */
struct msgb *ranap_new_msg_sec_mod_cmd(const uint8_t *ik, const uint8_t *ck, enum RANAP_KeyStatus status);

/*! \brief generate RANAP SECURITY MODE COMPLETE message */
struct msgb *ranap_new_msg_sec_mod_compl(
	RANAP_ChosenIntegrityProtectionAlgorithm_t chosen_ip_alg,
	RANAP_ChosenEncryptionAlgorithm_t chosen_enc_alg);

/*! \brief generate RANAP COMMON ID message */
struct msgb *ranap_new_msg_common_id(const char *imsi);

/*! \brief generate RANAP IU RELEASE COMMAND message */
struct msgb *ranap_new_msg_iu_rel_cmd(const RANAP_Cause_t *cause_in);

/*! \brief generate RAPAP IU RELEASE COMPLETE message */
struct msgb *ranap_new_msg_iu_rel_compl(void);

/*! \brief generate RANAP PAGING COMMAND message */
struct msgb *ranap_new_msg_paging_cmd(const char *imsi, const uint32_t *tmsi, int is_ps, uint32_t cause);

/*! \brief generate RANAP RAB ASSIGNMENT REQUEST message for CS (voice) */
struct msgb *ranap_new_msg_rab_assign_voice(uint8_t rab_id, uint32_t rtp_ip,
					    uint16_t rtp_port,
					    bool use_x213_nsap);

/*! \brief generate RANAP RAB ASSIGNMENT REQUEST message for PS (data) */
struct msgb *ranap_new_msg_rab_assign_data(uint8_t rab_id, uint32_t gtp_ip,
					   uint32_t gtp_tei, bool use_x213_nsap);

/*! \brief generate RANAP RESET message */
struct msgb *ranap_new_msg_reset(RANAP_CN_DomainIndicator_t domain,
				 const RANAP_Cause_t *cause);

/*! \brief generate RANAP RESET ACK message */
struct msgb *ranap_new_msg_reset_ack(RANAP_CN_DomainIndicator_t domain,
				     RANAP_GlobalRNC_ID_t *rnc_id);


/*! \brief generate RANAP INITIAL UE message */
struct msgb *ranap_new_msg_initial_ue(uint32_t conn_id, int is_ps,
				     RANAP_GlobalRNC_ID_t *rnc_id,
				     uint8_t *nas_pdu, unsigned int nas_len);

/*! \brief generate RANAP IU RELEASE REQUEST message */
struct msgb *ranap_new_msg_iu_rel_req(const RANAP_Cause_t *cause);

/*! \brief generate RANAP RAB RELEASE REQUEST message */
struct msgb *ranap_new_msg_rab_rel_req(uint8_t rab_id, const RANAP_Cause_t *cause);
