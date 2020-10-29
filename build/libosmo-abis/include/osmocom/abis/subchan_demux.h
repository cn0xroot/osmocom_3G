#ifndef _SUBCH_DEMUX_H
#define _SUBCH_DEMUX_H
/* A E1 sub-channel (de)multiplexer with TRAU frame sync */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdint.h>
#include <osmocom/core/linuxlist.h>

/*! \defgroup subchan_demux
 *  \brief E1 sub-channel multiplexer/demultiplexer
 *  @{
 *
 *  \file subchan_demux.h
 */

/*! \brief number of 16k sub-channels inside one 64k E1 timeslot */
#define NR_SUBCH	4
/*! \brief size of TRAU frames in bytes */
#define TRAU_FRAME_SIZE	40
/*! \brief size of TRAU farmes in bits */
#define TRAU_FRAME_BITS	(TRAU_FRAME_SIZE*8)

/***********************************************************************/
/* DEMULTIPLEXER */
/***********************************************************************/

/*! \brief one subchannel inside the demultplexer */
struct demux_subch {
	/*! \brief bit-buffer for output bits */
	uint8_t out_bitbuf[TRAU_FRAME_BITS];
	/*! \brief next bit to be written in out_bitbuf */
	uint16_t out_idx;
	/*! \brief number of consecutive zeros that we have received (for sync) */
	unsigned int consecutive_zeros;
	/*! \brief  are we in TRAU frame sync or not? */
	unsigned int in_sync;
};

/*! \brief one instance of a subchannel demultiplexer */
struct subch_demux {
	/*! \brief bitmask of currently active subchannels */
	uint8_t chan_activ;
	/*! \brief one demux_subch struct for every subchannel */
	struct demux_subch subch[NR_SUBCH];
	/*! \brief callback to be called once we have received a
	 *  complete frame on a given subchannel */
	int (*out_cb)(struct subch_demux *dmx, int ch, uint8_t *data, int len,
		      void *);
	/*! \brief user-provided data, transparently passed to out_cb() */
	void *data;
};

int subch_demux_init(struct subch_demux *dmx);
int subch_demux_in(struct subch_demux *dmx, uint8_t *data, int len);
int subch_demux_activate(struct subch_demux *dmx, int subch);
int subch_demux_deactivate(struct subch_demux *dmx, int subch);

/***********************************************************************/
/* MULTIPLEXER */
/***********************************************************************/

/*! \brief one element in the tx_queue of a muxer sub-channel */
struct subch_txq_entry {
	/*! \brief internal linked list header */
	struct llist_head list;

	unsigned int bit_len;	/*!< \brief total number of bits in 'bits' */
	unsigned int next_bit;	/*!< \brief next bit to be transmitted */

	uint8_t bits[0];	/*!< \brief one bit per byte */
};

/*! \brief one sub-channel inside a multiplexer */
struct mux_subch {
	/*! \brief linked list of \ref subch_txq_entry */
	struct llist_head tx_queue;
};

/*! \brief one instance of the subchannel multiplexer */
struct subch_mux {
	/*! \brief array of sub-channels inside the multiplexer */
	struct mux_subch subch[NR_SUBCH];
};

int subchan_mux_init(struct subch_mux *mx);
int subchan_mux_out(struct subch_mux *mx, uint8_t *data, int len);
int subchan_mux_enqueue(struct subch_mux *mx, int s_nr, const uint8_t *data,
			int len);

/* }@ */

#endif /* _SUBCH_DEMUX_H */
