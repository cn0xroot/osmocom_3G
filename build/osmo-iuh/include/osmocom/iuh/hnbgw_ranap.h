#pragma once

#include <osmocom/iuh/hnbgw.h>

int hnbgw_ranap_rx(struct msgb *msg, uint8_t *data, size_t len);
int hnbgw_ranap_init(void);
