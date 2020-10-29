#ifndef _OSMO_ABIS_IPACCESS_H
#define _OSMO_ABIS_IPACCESS_H

#include <stdint.h>
#include <osmocom/gsm/protocol/ipaccess.h>

/* quick solution to get openBSC's ipaccess tools working. */
extern int ipaccess_fd_cb(struct osmo_fd *bfd, unsigned int what);

#endif /* _OSMO_ABIS_IPACCESS_H */
