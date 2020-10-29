#pragma once

#include <osmocom/crypt/auth.h>

int auc_compute_vectors(struct osmo_auth_vector *vec, unsigned int num_vec,
			struct osmo_sub_auth_data *aud2g,
			struct osmo_sub_auth_data *aud3g,
			const uint8_t *rand_auts, const uint8_t *auts);
