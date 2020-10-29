#define do_tlv_data_sm_resp( inst_tlv )\
U16( inst_tlv->, tag, str_tlv_id );\
U16( inst_tlv->, length, valueDec_16 );\
if( inst_tlv-> tag == TLVID_delivery_failure_reason ){\
    U08( inst_tlv->, value.val08, valueDec_08 );\
} else if( inst_tlv-> tag == TLVID_network_error_code ){\
    OCTET16( inst_tlv->, value.octet, 3 );\
} else if( inst_tlv-> tag == TLVID_additional_status_info_text ){\
    OCTET16( inst_tlv->, value.octet, 256 );\
} else if( inst_tlv-> tag == TLVID_dpf_result ){\
    U08( inst_tlv->, value.val08, valueDec_08 );\
} else {\
    OCTET16( inst_tlv->, value.octet, 1024 ) /* Parameter forwarded */\
};
