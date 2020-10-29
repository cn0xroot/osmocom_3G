#pragma once

#include <stdint.h>
#include <osmocom/core/msgb.h>

struct msgb *rua_new_udt(struct msgb *inmsg);
struct msgb *rua_new_conn(int is_ps, uint32_t context_id, struct msgb *inmsg);
struct msgb *rua_new_dt(int is_ps, uint32_t context_id, struct msgb *inmsg);
struct msgb *rua_new_disc(int is_ps, uint32_t context_id, struct msgb *inmsg);
