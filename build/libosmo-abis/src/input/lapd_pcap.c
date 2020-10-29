/* (C) 2008-2012 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * Author: Harald Welte <laforge@gnumonks.org>
 *         Pablo Neira Ayuso <pablo@gnumonks.org>
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

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>

#include <osmocom/abis/lapd_pcap.h>

/*
 * pcap writing of the mlapd load
 * pcap format is from http://wiki.wireshark.org/Development/LibpcapFileFormat
 */
#define DLT_LINUX_LAPD		177
#define LINUX_SLL_HOST		0
#define LINUX_SLL_OUTGOING	4

struct pcap_hdr {
	uint32_t magic_number;
	uint16_t version_major;
	uint16_t version_minor;
	int32_t  thiszone;
	uint32_t sigfigs;
	uint32_t snaplen;
	uint32_t network;
} __attribute__((packed));

struct pcap_rechdr {
	uint32_t ts_sec;
	uint32_t ts_usec;
	uint32_t incl_len;
	uint32_t orig_len;
} __attribute__((packed));

struct pcap_lapdhdr {
	uint16_t pkttype;
	uint16_t hatype;
	uint16_t halen;
	uint8_t addr[8];
	int16_t protocol;
} __attribute__((packed));

osmo_static_assert(offsetof(struct pcap_lapdhdr, hatype) == 2, hatype_offset);
osmo_static_assert(offsetof(struct pcap_lapdhdr, halen) == 4, halen_offset);
osmo_static_assert(offsetof(struct pcap_lapdhdr, addr) == 6, addr_offset);
osmo_static_assert(offsetof(struct pcap_lapdhdr, protocol) == 14, proto_offset);
osmo_static_assert(sizeof(struct pcap_lapdhdr) == 16, lapd_header_size);

int osmo_pcap_lapd_set_fd(int fd)
{
		struct pcap_hdr pcap_header = {
		.magic_number	= 0xa1b2c3d4,
		.version_major	= 2,
		.version_minor	= 4,
		.thiszone	= 0,
		.sigfigs	= 0,
		.snaplen	= 65535,
		.network	= DLT_LINUX_LAPD,
	};

	if (write(fd, &pcap_header, sizeof(pcap_header))
					!= sizeof(pcap_header)) {
		LOGP(DLLAPD, LOGL_ERROR, "cannot write PCAP header: %s\n",
			strerror(errno));
		close(fd);
		return -1;
	}

	return 0;
}

int osmo_pcap_lapd_open(char *filename, mode_t mode)
{
	int fd, rc;

	LOGP(DLLAPD, LOGL_NOTICE, "opening LAPD pcap file `%s'\n", filename);

	fd = open(filename, O_WRONLY|O_TRUNC|O_CREAT, mode);
	if (fd < 0) {
		LOGP(DLLAPD, LOGL_ERROR, "failed to open PCAP file: %s\n",
			strerror(errno));
		return -1;
	}

	rc = osmo_pcap_lapd_set_fd(fd);
	if (rc < 0) {
		close(fd);
		return rc;
	}

	return fd;
}

/* This currently only works for the D-Channel */
int osmo_pcap_lapd_write(int fd, int direction, struct msgb *msg)
{
	int numbytes = 0;
	struct timeval tv;
	struct pcap_rechdr pcap_rechdr;
	struct pcap_lapdhdr header;
	char buf[sizeof(struct pcap_rechdr) +
		 sizeof(struct pcap_lapdhdr) + msg->len];

	/* PCAP file has not been opened, skip. */
	if (fd < 0)
		return 0;

	pcap_rechdr.ts_sec	= 0;
	pcap_rechdr.ts_usec	= 0;
	pcap_rechdr.incl_len   = msg->len + sizeof(struct pcap_lapdhdr);
	pcap_rechdr.orig_len   = msg->len + sizeof(struct pcap_lapdhdr);

	if (direction == OSMO_LAPD_PCAP_OUTPUT)
		header.pkttype		= htons(LINUX_SLL_OUTGOING);
	else
		header.pkttype		= htons(LINUX_SLL_HOST);
	header.hatype		= 0;
	header.halen		= 0;
	header.addr[0]		= 0x01;	/* we are the network side */
	header.protocol		= ntohs(48);

	gettimeofday(&tv, NULL);
	pcap_rechdr.ts_sec = tv.tv_sec;
	pcap_rechdr.ts_usec = tv.tv_usec;

	memcpy(buf + numbytes, &pcap_rechdr, sizeof(pcap_rechdr));
	numbytes += sizeof(pcap_rechdr);

	memcpy(buf + numbytes, &header, sizeof(header));
	numbytes += sizeof(header);

	memcpy(buf + numbytes, msg->data, msg->len);
	numbytes += msg->len;

	if (write(fd, buf, numbytes) != numbytes) {
		LOGP(DLLAPD, LOGL_ERROR, "cannot write packet to PCAP: %s\n",
			strerror(errno));
		return -1;
	}
	return numbytes;
}

int osmo_pcap_lapd_close(int fd)
{
	LOGP(DLLAPD, LOGL_NOTICE, "closing LAPD pcap file\n");
	return close(fd);
}
