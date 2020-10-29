#pragma once

#include <stdint.h>

int rand_init(void);

int rand_get(uint8_t *rand, unsigned int len);
