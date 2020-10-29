/* (C) 2011 by Harald Welte <laforge@gnumonks.org>
 * (C) 2011 by On-Waves e.h.f
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

/*! \file osmo_ortp.c
 *  \brief Integration of libortp into osmocom framework (select, logging)
 */

#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <netdb.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/select.h>
#include <osmocom/trau/osmo_ortp.h>

#include <ortp/ortp.h>
#include <ortp/rtp.h>
#include <ortp/port.h>
#include <ortp/rtpsession.h>

#include "config.h"

static PayloadType *payload_type_efr;
static PayloadType *payload_type_hr;
static RtpProfile *osmo_pt_profile;

static void *tall_rtp_ctx;

/* malloc integration */

static void *osmo_ortp_malloc(size_t sz)
{
	return talloc_size(tall_rtp_ctx, sz);
}

static void *osmo_ortp_realloc(void *ptr, size_t sz)
{
	return talloc_realloc_size(tall_rtp_ctx, ptr, sz);
}

static void osmo_ortp_free(void *ptr)
{
	talloc_free(ptr);
}

static OrtpMemoryFunctions osmo_ortp_memfn = {
	.malloc_fun = osmo_ortp_malloc,
	.realloc_fun = osmo_ortp_realloc,
	.free_fun = osmo_ortp_free
};

/* logging */

struct level_map {
	OrtpLogLevel ortp;
	int osmo_level;
};
static const struct level_map level_map[] = {
	{ ORTP_DEBUG,	LOGL_DEBUG },
	{ ORTP_MESSAGE, LOGL_INFO },
	{ ORTP_WARNING, LOGL_NOTICE },
	{ ORTP_ERROR,	LOGL_ERROR },
	{ ORTP_FATAL,	LOGL_FATAL },
};
static int ortp_to_osmo_lvl(OrtpLogLevel lev)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(level_map); i++) {
		if (level_map[i].ortp == lev)
			return level_map[i].osmo_level;
	}
	/* default */
	return LOGL_ERROR;
}

static void my_ortp_logfn(
#if HAVE_ORTP_LOG_DOMAIN
	const char *domain,
#endif
	OrtpLogLevel lev, const char *fmt, va_list args)
{
	osmo_vlogp(DLMIB, ortp_to_osmo_lvl(lev), __FILE__, 0,
		   0, fmt, args);
}

/* ORTP signal callbacks */

static void ortp_sig_cb_ssrc(RtpSession *rs, void *data)
{
	int port = rtp_session_get_local_port(rs);
	uint32_t ssrc = rtp_session_get_recv_ssrc(rs);

	LOGP(DLMIB, LOGL_INFO,
	     "osmo-ortp(%d): ssrc_changed to 0x%08x\n", port, ssrc);
}

static void ortp_sig_cb_pt(RtpSession *rs, void *data)
{
	int port = rtp_session_get_local_port(rs);
	int pt = rtp_session_get_recv_payload_type(rs);

	LOGP(DLMIB, LOGL_NOTICE,
	     "osmo-ortp(%d): payload_type_changed to 0x%02x\n", port, pt);
}

static void ortp_sig_cb_net(RtpSession *rs, void *data)
{
	int port = rtp_session_get_local_port(rs);

	LOGP(DLMIB, LOGL_ERROR,
	     "osmo-ortp(%d): network_error %s\n", port, (char *)data);
}

static void ortp_sig_cb_ts(RtpSession *rs, void *data)
{
	int port = rtp_session_get_local_port(rs);
	uint32_t ts = rtp_session_get_current_recv_ts(rs);

	LOGP(DLMIB, LOGL_NOTICE,
	     "osmo-ortp(%d): timestamp_jump, new TS %d, resyncing\n", port, ts);
	rtp_session_resync(rs);
}

static inline bool recv_with_cb(struct osmo_rtp_socket *rs)
{
	uint8_t *payload;
	mblk_t *mblk = rtp_session_recvm_with_ts(rs->sess, rs->rx_user_ts);
	if (!mblk)
		return false;

	int plen = rtp_get_payload(mblk, &payload);
	/* hand into receiver */
	if (rs->rx_cb && plen > 0)
		rs->rx_cb(rs, payload, plen, rtp_get_seqnumber(mblk),
			  rtp_get_timestamp(mblk), rtp_get_markbit(mblk));
	freemsg(mblk);
	if (plen > 0)
		return true;
	return false;
}

/*! \brief poll the socket for incoming data
 *  \param[in] rs the socket to be polled
 *  \returns number of packets received + handed to the rx_cb
 */
int osmo_rtp_socket_poll(struct osmo_rtp_socket *rs)
{
	if (rs->flags & OSMO_RTP_F_DISABLED)
		return 0;

	if (recv_with_cb(rs))
		return 1;

	LOGP(DLMIB, LOGL_INFO, "osmo_rtp_socket_poll(%u): ERROR!\n",
	     rs->rx_user_ts);
	return 0;
}

/* Osmo FD callbacks */

static int osmo_rtp_fd_cb(struct osmo_fd *fd, unsigned int what)
{
	struct osmo_rtp_socket *rs = fd->data;

	if (what & BSC_FD_READ) {
		/* in polling mode, we don't want to be called here */
		if (rs->flags & OSMO_RTP_F_POLL) {
			fd->when &= ~BSC_FD_READ;
			return 0;
		}
		if (!recv_with_cb(rs))
			LOGP(DLMIB, LOGL_INFO, "recvm_with_ts(%u): ERROR!\n",
			     rs->rx_user_ts);
		rs->rx_user_ts += 160;
	}
	/* writing is not queued at the moment, so BSC_FD_WRITE
	 * shouldn't occur */
	return 0;
}

static int osmo_rtcp_fd_cb(struct osmo_fd *fd, unsigned int what)
{
	struct osmo_rtp_socket *rs = fd->data;

	/* We probably don't need this at all, as
	 * rtp_session_recvm_with_ts() will alway also poll the RTCP
	 * file descriptor for new data */
	return rtp_session_rtcp_recv(rs->sess);
}

static int osmo_rtp_socket_fdreg(struct osmo_rtp_socket *rs)
{
	int rc;

	rs->rtp_bfd.fd = rtp_session_get_rtp_socket(rs->sess);
	rs->rtcp_bfd.fd = rtp_session_get_rtcp_socket(rs->sess);
	rs->rtp_bfd.when = rs->rtcp_bfd.when = BSC_FD_READ;
	rs->rtp_bfd.data = rs->rtcp_bfd.data = rs;
	rs->rtp_bfd.cb = osmo_rtp_fd_cb;
	rs->rtcp_bfd.cb = osmo_rtcp_fd_cb;

	rc = osmo_fd_register(&rs->rtp_bfd);
	if (rc < 0)
		return rc;

	rc = osmo_fd_register(&rs->rtcp_bfd);
	if (rc < 0) {
		osmo_fd_unregister(&rs->rtp_bfd);
		return rc;
	}

	return 0;
}

static void create_payload_types()
{
	PayloadType *pt;

	/* EFR */
	pt = payload_type_new();
	pt->type = PAYLOAD_AUDIO_PACKETIZED;
	pt->clock_rate = 8000;
	pt->mime_type = "EFR";
	pt->normal_bitrate = 12200;
	pt->channels = 1;
	payload_type_efr = pt;

	/* HR */
	pt = payload_type_new();
	pt->type = PAYLOAD_AUDIO_PACKETIZED;
	pt->clock_rate = 8000;
	pt->mime_type = "HR";
	pt->normal_bitrate = 6750; /* FIXME */
	pt->channels = 1;
	payload_type_hr = pt;

	/* create a new RTP profile as clone of AV profile */
	osmo_pt_profile = rtp_profile_clone(&av_profile);

	/* add the GSM specific payload types. They are all dynamically
	 * assigned, but in the Osmocom GSM system we have allocated
	 * them as follows: */
	rtp_profile_set_payload(osmo_pt_profile, RTP_PT_GSM_EFR, payload_type_efr);
	rtp_profile_set_payload(osmo_pt_profile, RTP_PT_GSM_HALF, payload_type_hr);
	rtp_profile_set_payload(osmo_pt_profile, RTP_PT_AMR, &payload_type_amr);
}

/* public functions */

/*! \brief initialize Osmocom RTP code
 *  \param[in] ctx default talloc context for library-internal allocations
 */
void osmo_rtp_init(void *ctx)
{
	tall_rtp_ctx = ctx;
	ortp_set_memory_functions(&osmo_ortp_memfn);
	ortp_init();
	ortp_set_log_level_mask(
#if HAVE_ORTP_LOG_DOMAIN
		ORTP_LOG_DOMAIN,
#endif
		0xffff);

	ortp_set_log_handler(my_ortp_logfn);
	create_payload_types();
}

/*! \brief Set Osmocom RTP socket parameters
 *  \param[in] rs OsmoRTP socket
 *  \param[in] param defined which parameter to set
                     OSMO_RTP_P_JITBUF - enables regular jitter buffering
                     OSMO_RTP_P_JIT_ADAP - enables adaptive jitter buffering
 *  \param[in] val Size of jitter buffer (in ms), 0 means disable buffering
 *  \returns negative value on error, 0 or 1 otherwise
                      (depending on whether given jitter buffering is enabled)
 */
int osmo_rtp_socket_set_param(struct osmo_rtp_socket *rs,
			      enum osmo_rtp_param param, int val)
{
	switch (param) {
	case OSMO_RTP_P_JIT_ADAP:
		rtp_session_enable_adaptive_jitter_compensation(rs->sess,
								(bool)val);
		/* fall-through on-purpose - we have to set val anyway */
	case OSMO_RTP_P_JITBUF:
		rtp_session_enable_jitter_buffer(rs->sess,
			(val) ? TRUE : FALSE);
		if (val)
			rtp_session_set_jitter_compensation(rs->sess, val);
		break;
	default:
		return -EINVAL;
	}
	if (param == OSMO_RTP_P_JIT_ADAP)
		return rtp_session_adaptive_jitter_compensation_enabled(rs->sess);
	return rtp_session_jitter_buffer_enabled(rs->sess);
}

/*! \brief Create a new RTP socket
 *  \param[in] talloc_cxt talloc context for this allocation. NULL for
 *  			  dafault context
 *  \param[in] flags Flags like OSMO_RTP_F_POLL
 *  \returns pointer to library-allocated \a struct osmo_rtp_socket
 */
struct osmo_rtp_socket *osmo_rtp_socket_create(void *talloc_ctx, unsigned int flags)
{
	struct osmo_rtp_socket *rs;

	if (!talloc_ctx)
		talloc_ctx = tall_rtp_ctx;

	rs = talloc_zero(talloc_ctx, struct osmo_rtp_socket);
	if (!rs)
		return NULL;

	rs->flags = OSMO_RTP_F_DISABLED | flags;
	rs->sess = rtp_session_new(RTP_SESSION_SENDRECV);
	if (!rs->sess) {
		talloc_free(rs);
		return NULL;
	}
	rtp_session_set_data(rs->sess, rs);
	rtp_session_set_profile(rs->sess, osmo_pt_profile);
	rtp_session_set_jitter_compensation(rs->sess, 100);

	rtp_session_signal_connect(rs->sess, "ssrc_changed",
				   (RtpCallback) ortp_sig_cb_ssrc,
				   (unsigned long) rs);
	rtp_session_signal_connect(rs->sess, "payload_type_changed",
				   (RtpCallback) ortp_sig_cb_pt,
				   (unsigned long) rs);
	rtp_session_signal_connect(rs->sess, "network_error",
				   (RtpCallback) ortp_sig_cb_net,
				   (unsigned long) rs);
	rtp_session_signal_connect(rs->sess, "timestamp_jump",
				   (RtpCallback) ortp_sig_cb_ts,
				   (unsigned long) rs);

	/* initialize according to the RFC */
	rtp_session_set_seq_number(rs->sess, random());
	rs->tx_timestamp = random();
	

	return rs;
}

/*! \brief bind a RTP socket to a local port
 *  \param[in] rs OsmoRTP socket
 *  \param[in] ip hostname/ip as string
 *  \param[in] port UDP port number, -1 for random selection
 *  \returns 0 on success, <0 on error
 */
int osmo_rtp_socket_bind(struct osmo_rtp_socket *rs, const char *ip, int port)
{
	int rc, rtcp = (-1 != port) ? port + 1 : -1;
	rc = rtp_session_set_local_addr(rs->sess, ip, port, rtcp);

	if (rc < 0)
		return rc;

	rs->rtp_bfd.fd = rtp_session_get_rtp_socket(rs->sess);
	rs->rtcp_bfd.fd = rtp_session_get_rtcp_socket(rs->sess);

	return 0;
}

/*! \brief connect a OsmoRTP socket to a remote port
 *  \param[in] rs OsmoRTP socket
 *  \param[in] ip String representation of remote hostname or IP address
 *  \param[in] port UDP port number to connect to
 *
 *  If the OsmoRTP socket is not in POLL mode, this function will also
 *  cause the RTP and RTCP file descriptors to be registred with the
 *  libosmocore select() loop integration.
 *
 *  \returns 0 on success, <0 in case of error
 */
int osmo_rtp_socket_connect(struct osmo_rtp_socket *rs, const char *ip, uint16_t port)
{
	int rc;
	if (!port) {
		LOGP(DLMIB, LOGL_INFO, "osmo_rtp_socket_connect() refused to "
		     "set remote %s:%u\n", ip, port);
		return 0;
	}

	/* We don't want the connected mode enabled during
	 * rtp_session_set_remote_addr(), because that will already setup a
	 * connection and updating the remote address will no longer have an
	 * effect. Contrary to what one may expect, this must be 0 at first,
	 * and we're setting to 1 further down to establish a connection once
	 * the first RTP packet is received (OS#1661). */
	rtp_session_set_connected_mode(rs->sess, 0);

	rc = rtp_session_set_remote_addr(rs->sess, ip, port);
	if (rc < 0)
		return rc;

	/* enable the use of connect() so later getsockname() will
	 * actually return the IP address that was chosen for the local
	 * sid of the connection */
	rtp_session_set_connected_mode(rs->sess, 1);
	rs->flags &= ~OSMO_RTP_F_DISABLED;

	if (rs->flags & OSMO_RTP_F_POLL)
		return rc;
	else
		return osmo_rtp_socket_fdreg(rs);
}

/*! \brief Send one RTP frame via a RTP socket
 *  \param[in] rs OsmoRTP socket
 *  \param[in] payload pointer to buffer with RTP payload data
 *  \param[in] payload_len length of \a payload in bytes
 *  \param[in] duration duration in number of RTP clock ticks
 *  \returns 0 on success, <0 in case of error.
 */
int osmo_rtp_send_frame(struct osmo_rtp_socket *rs, const uint8_t *payload,
			unsigned int payload_len, unsigned int duration)
{
	return osmo_rtp_send_frame_ext(rs, payload, payload_len, duration,
				       false);
}

/*! \brief Send one RTP frame via a RTP socket
 *  \param[in] rs OsmoRTP socket
 *  \param[in] payload pointer to buffer with RTP payload data
 *  \param[in] payload_len length of \a payload in bytes
 *  \param[in] duration duration in number of RTP clock ticks
 *  \param[in] marker the status of Marker bit in RTP header
 *  \returns 0 on success, <0 in case of error.
 */
int osmo_rtp_send_frame_ext(struct osmo_rtp_socket *rs, const uint8_t *payload,
			unsigned int payload_len, unsigned int duration,
			bool marker)
{
	mblk_t *mblk;
	int rc;

	if (rs->flags & OSMO_RTP_F_DISABLED)
		return 0;

	mblk = rtp_session_create_packet(rs->sess, RTP_FIXED_HEADER_SIZE,
					 payload, payload_len);
	if (!mblk)
		return -ENOMEM;

	rtp_set_markbit(mblk, marker);
	rs->tx_timestamp += duration;
	rc = rtp_session_sendm_with_ts(rs->sess, mblk,
				       rs->tx_timestamp);
	if (rc < 0) {
		/* no need to free() the mblk, as rtp_session_rtp_send()
		 * unconditionally free()s the mblk even in case of
		 * error */
		return rc;
	}

	return rc;
}

/*! \brief Set the payload type of a RTP socket
 *  \param[in] rs OsmoRTP socket
 *  \param[in] payload_type RTP payload type
 *  \returns 0 on success, < 0 otherwise
 */
int osmo_rtp_socket_set_pt(struct osmo_rtp_socket *rs, int payload_type)
{
	int rc;

	rc = rtp_session_set_payload_type(rs->sess, payload_type);
	//rtp_session_set_rtcp_report_interval(rs->sess, 5*1000);

	return rc;
}

/*! \brief completely close the RTP socket and release all resources
 *  \param[in] rs OsmoRTP socket to be released
 *  \returns 0 on success
 */
int osmo_rtp_socket_free(struct osmo_rtp_socket *rs)
{
	if (rs->rtp_bfd.list.next && rs->rtp_bfd.list.next != LLIST_POISON1)
		osmo_fd_unregister(&rs->rtp_bfd);

	if (rs->rtcp_bfd.list.next && rs->rtcp_bfd.list.next != LLIST_POISON1)
		osmo_fd_unregister(&rs->rtcp_bfd);

	if (rs->sess) {
		rtp_session_release_sockets(rs->sess);
		rtp_session_destroy(rs->sess);
		rs->sess = NULL;
	}

	talloc_free(rs);

	return 0;
}

/*! \brief obtain the locally bound IPv4 address and UDP port
 *  \param[in] rs OsmoRTP socket
 *  \param[out] ip Pointer to caller-allocated uint32_t for IPv4 address
 *  \oaram[out] port Pointer to caller-allocated int for UDP port number
 *  \returns 0 on success, <0 on error, -EIO in case of IPv6 socket
 */
int osmo_rtp_get_bound_ip_port(struct osmo_rtp_socket *rs,
			       uint32_t *ip, int *port)
{
	int rc;
	struct sockaddr_storage ss;
	struct sockaddr_in *sin = (struct sockaddr_in *) &ss;
	socklen_t alen = sizeof(ss);

	rc = getsockname(rs->rtp_bfd.fd, (struct sockaddr *)&ss, &alen);
	if (rc < 0)
		return rc;

	if (ss.ss_family != AF_INET)
		return -EIO;

	*ip = ntohl(sin->sin_addr.s_addr);
	*port = rtp_session_get_local_port(rs->sess);

	return 0;
}

/*! \brief obtain the locally bound address and port
 *  \param[in] rs OsmoRTP socket
 *  \param[out] addr caller-allocated char ** to which the string pointer for
 *  		     the address is stored
 *  \param[out] port caller-allocated int * to which the port number is
 *  		     stored
 *  \returns 0 on success, <0 in case of error
 */
int osmo_rtp_get_bound_addr(struct osmo_rtp_socket *rs,
			    const char **addr, int *port)
{
	int rc;
	struct sockaddr_storage ss;
	socklen_t alen = sizeof(ss);
	static char hostbuf[256];

	memset(hostbuf, 0, sizeof(hostbuf));

	rc = getsockname(rs->rtp_bfd.fd, (struct sockaddr *)&ss, &alen);
	if (rc < 0)
		return rc;

	rc = getnameinfo((struct sockaddr *)&ss, alen,
			 hostbuf, sizeof(hostbuf), NULL, 0,
			 NI_NUMERICHOST);
	if (rc < 0)
		return rc;

	*port = rtp_session_get_local_port(rs->sess);
	*addr = hostbuf;

	return 0;
}


void osmo_rtp_socket_log_stats(struct osmo_rtp_socket *rs,
				int subsys, int level,
				const char *pfx)
{
	const rtp_stats_t *stats;

	stats = rtp_session_get_stats(rs->sess);
	if (!stats)
		return;

	LOGP(subsys, level, "%sRTP Tx(%"PRIu64" pkts, %"PRIu64" bytes) "
		"Rx(%"PRIu64" pkts, %"PRIu64" bytes, %"PRIu64" late, "
		"%"PRIu64" loss, %"PRIu64" qmax)\n",
		pfx, stats->packet_sent, stats->sent,
		stats->packet_recv, stats->hw_recv, stats->outoftime,
		stats->cum_packet_loss, stats->discarded);
}

void osmo_rtp_socket_stats(struct osmo_rtp_socket *rs,
		uint32_t *sent_packets, uint32_t *sent_octets,
		uint32_t *recv_packets, uint32_t *recv_octets,
		uint32_t *recv_lost, uint32_t *last_jitter)
{
	const rtp_stats_t *stats;

	*sent_packets = *sent_octets = *recv_packets = *recv_octets = 0;
	*recv_lost = *last_jitter = 0;

	stats = rtp_session_get_stats(rs->sess);
	if (stats) {
		/* truncate from 64bit to 32bit here */
		*sent_packets = stats->packet_sent;
		*sent_octets = stats->sent;
		*recv_packets = stats->packet_recv;
		*recv_octets = stats->recv;
		*recv_lost = stats->cum_packet_loss;
	}

	const jitter_stats_t *jitter;

	jitter = rtp_session_get_jitter_stats(rs->sess);
	if (jitter)
		*last_jitter = jitter->jitter;
}
