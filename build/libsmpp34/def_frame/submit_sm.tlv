#define do_tlv_submit_sm( inst_tlv )\
U16( inst_tlv->, tag, str_tlv_id );\
U16( inst_tlv->, length, valueDec_16 );\
if( inst_tlv-> tag == TLVID_user_message_reference ){\
    U16( inst_tlv->, value.val16, valueDec_16 );\
} else if( inst_tlv-> tag == TLVID_source_port ){\
    U16( inst_tlv->, value.val16, valueDec_16 );\
} else if( inst_tlv-> tag == TLVID_source_addr_subunit ){\
    U08( inst_tlv->, value.val08, valueDec_08 );\
} else if( inst_tlv-> tag == TLVID_destination_port ){\
    U16( inst_tlv->, value.val16, valueDec_16 );\
} else if( inst_tlv-> tag == TLVID_dest_addr_subunit ){\
    U08( inst_tlv->, value.val08, valueDec_08 );\
} else if( inst_tlv-> tag == TLVID_sar_msg_ref_num ){\
    U16( inst_tlv->, value.val16, valueDec_16 );\
} else if( inst_tlv-> tag == TLVID_sar_total_segments ){\
    U08( inst_tlv->, value.val08, valueDec_08 );\
} else if( inst_tlv-> tag == TLVID_sar_segment_seqnum ){\
    U08( inst_tlv->, value.val08, valueDec_08 );\
} else if( inst_tlv-> tag == TLVID_more_messages_to_send ){\
    U08( inst_tlv->, value.val08, valueDec_08 );\
} else if( inst_tlv-> tag == TLVID_payload_type ){\
    U08( inst_tlv->, value.val08, valueDec_08 );\
} else if( inst_tlv-> tag == TLVID_message_payload ){\
    OCTET16( inst_tlv->, value.octet, 1024 );\
} else if( inst_tlv-> tag == TLVID_privacy_indicator ){\
    U08( inst_tlv->, value.val08, valueDec_08 );\
} else if( inst_tlv-> tag == TLVID_callback_num ){\
    OCTET16( inst_tlv->, value.octet, 19 );\
} else if( inst_tlv-> tag == TLVID_callback_num_pres_ind ){\
    U08( inst_tlv->, value.val08, valueDec_08 );\
} else if( inst_tlv-> tag == TLVID_callback_num_atag ){\
    OCTET16( inst_tlv->, value.octet, 65 );\
} else if( inst_tlv-> tag == TLVID_source_subaddress ){\
    OCTET16( inst_tlv->, value.octet, 23 );\
} else if( inst_tlv-> tag == TLVID_dest_subaddress ){\
    OCTET16( inst_tlv->, value.octet, 23 );\
} else if( inst_tlv-> tag == TLVID_user_response_code ){\
    U08( inst_tlv->, value.val08, valueDec_08 );\
} else if( inst_tlv-> tag == TLVID_display_time ){\
    U08( inst_tlv->, value.val08, valueDec_08 );\
} else if( inst_tlv-> tag == TLVID_sms_signal ){\
    U16( inst_tlv->, value.val16, valueDec_16 );\
} else if( inst_tlv-> tag == TLVID_ms_validity ){\
    U08( inst_tlv->, value.val08, valueDec_08 );\
} else if( inst_tlv-> tag == TLVID_ms_msg_wait_facilities ){\
    U08( inst_tlv->, value.val08, valueDec_08 );\
} else if( inst_tlv-> tag == TLVID_number_of_messages ){\
    U08( inst_tlv->, value.val08, valueDec_08 );\
} else if( inst_tlv-> tag == TLVID_alert_on_message_delivery ){\
    OCTET16( inst_tlv->, value.octet, 0 ); /* WARNING */\
} else if( inst_tlv-> tag == TLVID_language_indicator ){\
    U08( inst_tlv->, value.val08, valueDec_08 );\
} else if( inst_tlv-> tag == TLVID_its_reply_type ){\
    U08( inst_tlv->, value.val08, valueDec_08 );\
} else if( inst_tlv-> tag == TLVID_its_session_info ){\
    U16( inst_tlv->, value.val16, valueDec_16 );\
} else if( inst_tlv-> tag == TLVID_ussd_service_op ){\
    OCTET16( inst_tlv->, value.octet, 1 ); /* WARNING */\
} else if( inst_tlv-> tag > 0x13FF && inst_tlv-> tag < 0x4000 ){\
    OCTET16( inst_tlv->, value.octet, 1024 )\
} else if( inst_tlv-> tag > 0x3FFF && inst_tlv-> tag < 0xFFFF ){\
    OCTET16( inst_tlv->, value.octet, 1024 )\
} else {\
    OCTET16( inst_tlv->, value.octet, 1024 ) /* Parameter forwarded */\
};
