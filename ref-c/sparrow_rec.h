#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "sparrow_param.h"

#ifndef _SPARROW_REC_H_
#define _SPARROW_REC_H_

int help_rec(int v);
void help_recvec(int64_t *v, racc_ciphertext_t *ct);
int closest_v(int w, int b);
int rec_element(int w, int b);
void rec_vec(uint8_t *K, const int64_t *v, const racc_ciphertext_t *ct);

#endif