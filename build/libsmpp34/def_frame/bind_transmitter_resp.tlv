#define do_tlv_bind_transmitter_resp( inst_tlv )\
U16( inst_tlv->, tag, str_tlv_id );\
U16( inst_tlv->, length, valueDec_16 );\
if( inst_tlv-> tag == TLVID_sc_interface_version ){\
    U08( inst_tlv->, value.val08, valueDec_08 );\
} else {\
    OCTET16( inst_tlv->, value.octet, 1024 ) /* Parameter forwarded */\
};
