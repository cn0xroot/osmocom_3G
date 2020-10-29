#pragma once

#include <unistd.h>

#include "asn_system.h"
#include "BIT_STRING.h"
#include "OCTET_STRING.h"

void asn1_u32_to_bitstring(BIT_STRING_t *bitstr, uint32_t *buf, uint32_t in);
void asn1_u28_to_bitstring(BIT_STRING_t *bitstr, uint32_t *buf, uint32_t in);
void asn1_u24_to_bitstring(BIT_STRING_t *bitstr, uint32_t *buf, uint32_t in);
int BIT_STRING_fromBuf(BIT_STRING_t *st, const uint8_t *str, unsigned int bit_len);
void asn1_u32_to_str(OCTET_STRING_t *str, uint32_t *buf, uint32_t in);
void asn1_u16_to_str(OCTET_STRING_t *str, uint16_t *buf, uint16_t in);
void asn1_u8_to_str(OCTET_STRING_t *str, uint8_t *buf, uint8_t in);
int asn1_strncpy(char *out, const OCTET_STRING_t *in, size_t n);
uint32_t asn1str_to_u32(const OCTET_STRING_t *in);
uint16_t asn1str_to_u16(const OCTET_STRING_t *in);
uint8_t asn1str_to_u8(const OCTET_STRING_t *in);
uint32_t asn1bitstr_to_u32(const BIT_STRING_t *in);
uint32_t asn1bitstr_to_u28(const BIT_STRING_t *in);
uint32_t asn1bitstr_to_u24(const BIT_STRING_t *in);

static inline void OCTET_STRING_noalloc(OCTET_STRING_t *s, const uint8_t *str, int size)
{
	s->buf = str;
	s->size = size;
}
