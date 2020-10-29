/* 
 * Copyright (C) 2006 Raul Tremsal
 * File  : smpp34.h
 * Author: Raul Tremsal <ultraismo@yahoo.com>
 *
 * This file is part of libsmpp34 (c-open-smpp3.4 library).
 *
 * The libsmpp34 library is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU Lesser General Public License as 
 * published by the Free Software Foundation; either version 2.1 of the 
 * License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public 
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License 
 * along with this library; if not, write to the Free Software Foundation, 
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
 *
 */
#ifndef _SMPP_H_
#define _SMPP_H_

/* SMPP Version ***************************************************************/
#define SMPP_VERSION 0x34
/* Command Id *****************************************************************/
#define GENERIC_NACK 0x80000000 
#define BIND_RECEIVER 0x00000001 
#define BIND_RECEIVER_RESP 0x80000001 
#define BIND_TRANSMITTER 0x00000002 
#define BIND_TRANSMITTER_RESP 0x80000002 
#define QUERY_SM 0x00000003 
#define QUERY_SM_RESP 0x80000003 
#define SUBMIT_SM 0x00000004 
#define SUBMIT_SM_RESP 0x80000004 
#define DELIVER_SM 0x00000005 
#define DELIVER_SM_RESP 0x80000005 
#define UNBIND 0x00000006 
#define UNBIND_RESP 0x80000006 
#define REPLACE_SM 0x00000007 
#define REPLACE_SM_RESP 0x80000007 
#define CANCEL_SM 0x00000008 
#define CANCEL_SM_RESP 0x80000008 
#define BIND_TRANSCEIVER 0x00000009 
#define BIND_TRANSCEIVER_RESP 0x80000009 
/* Reserved 0x0000000A 0x8000000A */
#define OUTBIND 0x0000000B 
/* Reserved 0x0000000C - 0x00000014 0x8000000B - 0x80000014 */
#define ENQUIRE_LINK 0x00000015 
#define ENQUIRE_LINK_RESP 0x80000015 
/* Reserved 0x00000016 - 0x00000020 0x80000016 - 0x80000020*/
#define SUBMIT_MULTI 0x00000021 
#define SUBMIT_MULTI_RESP 0x80000021 
/* Reserved 0x00000022 - 0x000000FF 0x80000022 - 0x800000FF */
/* Reserved 0x00000100 */
#define Reserved 0x80000100 
/* Reserved 0x00000101 0x80000101 */
#define ALERT_NOTIFICATION 0x00000102 
/* Reserved 0x80000102 */
#define DATA_SM 0x00000103 
#define DATA_SM_RESP 0x80000103 
/* Reserved for SMPP extension 0x00000104 - 0x0000FFFF 0x80000104 - 0x8000FFFF */
/* Reserved 0x00010000 - 0x000101FF 0x80010000 - 0x800101FF */
/* Reserved for SMSC Vendor 0x00010200 - 0x000102FF 0x80010200 - 0x800102FF */
/* Reserved 0x00010300 - 0xFFFFFFFF*/


/* Command status *************************************************************/
#define ESME_ROK 0x00000000 /* No Error */
#define ESME_RINVMSGLEN 0x00000001 /* Message Length is invalid */
#define ESME_RINVCMDLEN 0x00000002 /* Command Length is invalid */
#define ESME_RINVCMDID 0x00000003 /* Invalid Command ID */
#define ESME_RINVBNDSTS 0x00000004 /* Incorrect BIND Status for given command */
#define ESME_RALYBND 0x00000005 /* ESME Already in Bound State */
#define ESME_RINVPRTFLG 0x00000006 /* Invalid Priority Flag */
#define ESME_RINVREGDLVFLG 0x00000007 /* Invalid Registered Delivery Flag */
#define ESME_RSYSERR 0x00000008 /* System Error */
/* Reserved 0x00000009 Reserved */
#define ESME_RINVSRCADR 0x0000000A /* Invalid Source Address */
#define ESME_RINVDSTADR 0x0000000B /* Invalid Dest Addr */
#define ESME_RINVMSGID 0x0000000C /* Message ID is invalid */
#define ESME_RBINDFAIL 0x0000000D /* Bind Failed */
#define ESME_RINVPASWD 0x0000000E /* Invalid Password */
#define ESME_RINVSYSID 0x0000000F /* Invalid System ID */
/* Reserved 0x00000010 Reserved */
#define ESME_RCANCELFAIL 0x00000011 /* Cancel SM Failed */
/* Reserved 0x00000012 Reserved */
#define ESME_RREPLACEFAIL 0x00000013 /* Replace SM Failed*/
#define ESME_RMSGQFUL 0x00000014 /* Message Queue Full */
#define ESME_RINVSERTYP 0x00000015 /* Invalid Service Type */
/* Reserved 0x00000016- 0x00000032 Reserved */
#define ESME_RINVNUMDESTS 0x00000033 /* Invalid number of destinations */
#define ESME_RINVDLNAME 0x00000034 /* Invalid Distribution List name */
/* Reserved 0x00000035- 0x0000003F Reserved */
#define ESME_RINVDESTFLAG 0x00000040 /* Destination flag is invalid (submit_multi) */
/* Reserved 0x00000041 Reserved */
#define ESME_RINVSUBREP 0x00000042 /* Invalid  submit with replace  request (i.e. submit_sm with replace_if_present_flag set) */
#define ESME_RINVESMCLASS 0x00000043 /* Invalid esm_class field data */
#define ESME_RCNTSUBDL 0x00000044 /* Cannot Submit to Distribution List */
#define ESME_RSUBMITFAIL 0x00000045 /* submit_sm or submit_multi failed */
/* Reserved 0x00000046- 0x00000047 Reserved */
#define ESME_RINVSRCTON 0x00000048 /* Invalid Source address TON */
#define ESME_RINVSRCNPI 0x00000049 /* Invalid Source address NPI */
#define ESME_RINVDSTTON 0x00000050 /* Invalid Destination address TON */
#define ESME_RINVDSTNPI 0x00000051 /* Invalid Destination address NPI */
/* Reserved 0x00000052 Reserved */
#define ESME_RINVSYSTYP 0x00000053 /* Invalid system_type field */
#define ESME_RINVREPFLAG 0x00000054 /* Invalid replace_if_present flag */
#define ESME_RINVNUMMSGS 0x00000055 /* Invalid number of messages */
/* Reserved 0x00000056- 0x00000057 Reserved */
#define ESME_RTHROTTLED 0x00000058 /* Throttling error (ESME has exceeded allowed message limits) */
/* Reserved 0x00000059- 0x00000060 Reserved*/
#define ESME_RINVSCHED 0x00000061 /* Invalid Scheduled Delivery Time */
#define ESME_RINVEXPIRY 0x00000062 /* Invalid message validity period (Expiry time) */
#define ESME_RINVDFTMSGID 0x00000063 /* Predefined Message Invalid or Not Found */
#define ESME_RX_T_APPN 0x00000064 /* ESME Receiver Temporary App Error Code */
#define ESME_RX_P_APPN 0x00000065 /* ESME Receiver Permanent App Error Code */
#define ESME_RX_R_APPN 0x00000066 /* ESME Receiver Reject Message Error Code */
#define ESME_RQUERYFAIL 0x00000067 /* query_sm request failed */
/* Reserved 0x00000068 - 0x000000BF Reserved */
#define ESME_RINVOPTPARSTREAM 0x000000C0 /* Error in the optional part of the PDU Body. */
#define ESME_ROPTPARNOTALLWD 0x000000C1 /* Optional Parameter not allowed */
#define ESME_RINVPARLEN 0x000000C2 /* Invalid Parameter Length. */
#define ESME_RMISSINGOPTPARAM 0x000000C3 /* Expected Optional Parameter missing */
#define ESME_RINVOPTPARAMVAL 0x000000C4 /* Invalid Optional Parameter Value */
/* Reserved 0x000000C5 - 0x000000FD Reserved */
#define ESME_RDELIVERYFAILURE 0x000000FE /* Delivery Failure (used for data_sm_resp) */
#define ESME_RUNKNOWNERR 0x000000FF /* Unknown Error */
/* Reserved for SMPP extension 0x00000100- 0x000003FF Reserved for SMPP extension */
/* Reserved for SMSC vendor specific errors 0x00000400- 0x000004FF Reserved for SMSC vendor specific errors */
/* Reserved 0x00000500- 0xFFFFFFFF Reserved */

/* ADDR_TON Values ************************************************************/
#define TON_Unknown           0
#define TON_International     1
#define TON_National          2
#define TON_Network_Specific  3
#define TON_Subscriber_Number 4
#define TON_Alphanumeric      5
#define TON_Abbreviated       6

/* ADDR_NPI Values ************************************************************/
#define NPI_Unknown             0
#define NPI_ISDN_E163_E164      1
#define NPI_Data_X121           3
#define NPI_Telex_F69           4
#define NPI_Land_Mobile_E212    6
#define NPI_National            8
#define NPI_Private             9
#define NPI_ERMES               10
#define NPI_Internet_IP         14
#define NPI_WAP_Client_Id       18


/* Flag which will identify whether destination address is a DL or SME Addr ***/
#define DFID_SME_Address            1
#define DFID_Distribution_List_Name 2

/* SMPP Optional Parameter Tag definitions ************************************/
#define TLVID_dest_addr_subunit           0x0005 /* GSM */
#define TLVID_dest_network_type           0x0006 /* Generic */
#define TLVID_dest_bearer_type            0x0007 /* Generic */
#define TLVID_dest_telematics_id          0x0008 /* GSM */
#define TLVID_source_addr_subunit         0x000D /* GSM */
#define TLVID_source_network_type         0x000E /* Generic */
#define TLVID_source_bearer_type          0x000F /* Generic */
#define TLVID_source_telematics_id        0x0010 /* GSM */
#define TLVID_qos_time_to_live            0x0017 /* Generic */
#define TLVID_payload_type                0x0019 /* Generic */
#define TLVID_additional_status_info_text 0x001D /* Generic */
#define TLVID_receipted_message_id        0x001E /* Generic */
#define TLVID_ms_msg_wait_facilities      0x0030 /* GSM */
#define TLVID_privacy_indicator           0x0201 /* CDMA, TDMA */
#define TLVID_source_subaddress           0x0202 /* CDMA, TDMA */
#define TLVID_dest_subaddress             0x0203 /* CDMA, TDMA */
#define TLVID_user_message_reference      0x0204 /* Generic */
#define TLVID_user_response_code          0x0205 /* CDMA, TDMA */
#define TLVID_source_port                 0x020A /* Generic */
#define TLVID_destination_port            0x020B /* Generic */
#define TLVID_sar_msg_ref_num             0x020C /* Generic */
#define TLVID_language_indicator          0x020D /* CDMA, TDMA */
#define TLVID_sar_total_segments          0x020E /* Generic */
#define TLVID_sar_segment_seqnum          0x020F /* Generic */
#define TLVID_sc_interface_version        0x0210 /* Generic */
#define TLVID_callback_num_pres_ind       0x0302 /* TDMA */
#define TLVID_callback_num_atag           0x0303 /* TDMA */
#define TLVID_number_of_messages          0x0304 /* CDMA */
#define TLVID_callback_num                0x0381 /* CDMA, TDMA, GSM, iDEN */
#define TLVID_dpf_result                  0x0420 /* Generic */
#define TLVID_set_dpf                     0x0421 /* Generic */
#define TLVID_ms_availability_status      0x0422 /* Generic */
#define TLVID_network_error_code          0x0423 /* Generic */
#define TLVID_message_payload             0x0424 /* Generic */
#define TLVID_delivery_failure_reason     0x0425 /* Generic */
#define TLVID_more_messages_to_send       0x0426 /* GSM */
#define TLVID_message_state               0x0427 /* Generic */
#define TLVID_ussd_service_op             0x0501 /* GSM (USSD) */
#define TLVID_display_time                0x1201 /* CDMA, TDMA */
#define TLVID_sms_signal                  0x1203 /* TDMA */
#define TLVID_ms_validity                 0x1204 /* CDMA, TDMA */
#define TLVID_alert_on_message_delivery   0x130C /* CDMA */
#define TLVID_its_reply_type              0x1380 /* CDMA */
#define TLVID_its_session_info            0x1383 /* CDMA */

#endif
