/*
 * (C) 2012 by Pablo Neira Ayuso <pablo@gnumonks.org>
 * (C) 2012 by On Waves ehf <http://www.on-waves.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdint.h>
#include <unistd.h>
#include <osmocom/netif/amr.h>

/* According to TS 26.101:
 *
 * Frame type    AMR code    bits  bytes
 *      0          4.75       95    12
 *      1          5.15      103    13
 *      2          5.90      118    15
 *      3          6.70      134    17
 *      4          7.40      148    19
 *      5          7.95      159    20
 *      6         10.20      204    26
 *      7         12.20      244    31
 */

static size_t amr_ft_to_bytes[AMR_FT_MAX] = {
	[AMR_FT_0]	= 12,
	[AMR_FT_1]	= 13,
	[AMR_FT_2]	= 15,
	[AMR_FT_3]	= 17,
	[AMR_FT_4]	= 19,
	[AMR_FT_5]	= 20,
	[AMR_FT_6]	= 26,
	[AMR_FT_7]	= 31,
	[AMR_FT_SID]	= 6,
};

size_t osmo_amr_bytes(uint8_t amr_ft)
{
	return amr_ft_to_bytes[amr_ft];
}

int osmo_amr_ft_valid(uint8_t amr_ft)
{
	/*
	 * Extracted from RFC3267:
	 *
	 * "... with a FT value in the range 9-14 for AMR ... the whole packet
	 *  SHOULD be discarded."
	 *
	 * "... packets containing only NO_DATA frames (FT=15) SHOULD NOT be
	 *  transmitted."
	 *
	 * So, let's discard frames with a AMR FT >= 9.
	 */
	if (amr_ft >= AMR_FT_MAX)
		return 0;

	return 1;
}
