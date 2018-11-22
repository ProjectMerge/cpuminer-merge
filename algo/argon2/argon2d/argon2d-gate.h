#ifndef ARGON2D_GATE_H__
#define ARGON2D_GATE_H__

#include "algo-gate-api.h"
#include <stdint.h>

void argon2m_hash( void *output, const void *input );
int scanhash_argon2m( int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done );
bool register_argon2m_algo( algo_gate_t* gate );

#endif

