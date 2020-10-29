#pragma once

#include <osmocom/iuh/hnbgw.h>

int hnbgw_hnbap_rx(struct hnb_context *hnb, struct msgb *msg);
int hnbgw_hnbap_init(void);
