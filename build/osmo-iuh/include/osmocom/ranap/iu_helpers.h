#pragma once

#include <stdint.h>
#include <sys/types.h>

int ranap_bcd_decode(char *out, size_t out_len, const uint8_t *in, size_t in_len);
int ranap_imsi_encode(uint8_t *out, size_t out_len, const char *in);
