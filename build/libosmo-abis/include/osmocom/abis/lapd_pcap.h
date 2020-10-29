#ifndef _LAPD_PCAP_H_
#define _LAPD_PCAP_H_

#include <sys/types.h>
#include <osmocom/core/msgb.h>

#define OSMO_LAPD_PCAP_INPUT	0
#define OSMO_LAPD_PCAP_OUTPUT	1

int osmo_pcap_lapd_open(char *filename, mode_t mode);
int osmo_pcap_lapd_set_fd(int fd);
int osmo_pcap_lapd_write(int fd, int direction, struct msgb *msg);
int osmo_pcap_lapd_close(int fd);

#endif
