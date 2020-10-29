#pragma once

#include <osmocom/iuh/hnbgw.h>

struct hnbgw_cnlink *hnbgw_cnlink_init(struct hnb_gw *gw, const char *host, uint16_t port, int is_ps);
