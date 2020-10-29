#define do_tlv_deliver_sm( inst_tlv )\
U16( inst_tlv->, tag, str_tlv_id );\
U16( inst_tlv->, length, valueDec_16 );\
if( inst_tlv-> tag == TLVID_user_message_reference ){\
    U16( inst_tlv->, value.val16, valueDec_16 );\
} else if( inst_tlv-> tag == TLVID_source_port ){\
    U16( inst_tlv->, value.val16, valueDec_16 );\
} else if( inst_tlv-> tag == TLVID_destination_port ){\
    U16( inst_tlv->, value.val16, valueDec_16 );\
} else if( inst_tlv-> tag == TLVID_sar_msg_ref_num ){\
    U16( inst_tlv->, value.val16, valueDec_16 );\
} else if( inst_tlv-> tag == TLVID_sar_total_segments ){\
    U08( inst_tlv->, value.val08, valueDec_08 );\
} else if( inst_tlv-> tag == TLVID_sar_segment_seqnum ){\
    U08( inst_tlv->, value.val08, valueDec_08 );\
} else if( inst_tlv-> tag == TLVID_user_response_code ){\
    U08( inst_tlv->, value.val08, valueDec_08 );\
} else if( inst_tlv-> tag == TLVID_privacy_indicator ){\
    U08( inst_tlv->, value.val08, valueDec_08 );\
} else if( inst_tlv-> tag == TLVID_payload_type ){\
    U08( inst_tlv->, value.val08, valueDec_08 );\
} else if( inst_tlv-> tag == TLVID_message_payload ){\
    OCTET16( inst_tlv->, value.octet, 1024 );\
} else if( inst_tlv-> tag == TLVID_callback_num ){\
    OCTET16( inst_tlv->, value.octet, 19 );\
} else if( inst_tlv-> tag == TLVID_source_subaddress ){\
    OCTET16( inst_tlv->, value.octet, 23 );\
} else if( inst_tlv-> tag == TLVID_dest_subaddress ){\
    OCTET16( inst_tlv->, value.octet, 23 );\
} else if( inst_tlv-> tag == TLVID_language_indicator ){\
    U08( inst_tlv->, value.val08, valueDec_08 );\
} else if( inst_tlv-> tag == TLVID_its_session_info ){\
    U16( inst_tlv->, value.val16, valueDec_16 );\
} else if( inst_tlv-> tag == TLVID_network_error_code ){\
    OCTET16( inst_tlv->, value.octet, 3 );\
} else if( inst_tlv-> tag == TLVID_message_state ){\
    U08( inst_tlv->, value.val08, valueDec_08 );\
} else if( inst_tlv-> tag == TLVID_receipted_message_id ){\
    OCTET16( inst_tlv->, value.octet, 65 );\
} else if( inst_tlv-> tag == TLVID_set_dpf ){ /* NO pertenece */\
    U08( inst_tlv->, value.val08, valueDec_08 );\
} else if( inst_tlv-> tag == TLVID_source_network_type ){ /* NO pertenece */\
    U08( inst_tlv->, value.val08, valueDec_08 );\
} else if( inst_tlv-> tag > 0x13FF && inst_tlv-> tag < 0x4000 ){\
    OCTET16( inst_tlv->, value.octet, 1024 )\
} else if( inst_tlv-> tag > 0x3FFF && inst_tlv-> tag < 0xFFFF ){\
    OCTET16( inst_tlv->, value.octet, 1024 )\
} else {\
    OCTET16( inst_tlv->, value.octet, 1024 ) /* Parameter forwarded */\
};
