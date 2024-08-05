//  racc_serial.h
//  Copyright (c) 2024 Sparrow KEM Team. See LICENSE.

//  === Raccoon signature scheme -- Serialize/deserialize.

#ifndef _SPARROW_SERIAL_H_
#define _SPARROW_SERIAL_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "sparrow_param.h"

//  === Global namespace prefix

#ifdef SPARROW_
#define racc_encode_pk SPARROW_(encode_pk)
#define racc_decode_pk SPARROW_(decode_pk)
#define racc_encode_sk SPARROW_(encode_sk)
#define racc_decode_sk SPARROW_(decode_sk)
#define racc_encode_sig SPARROW_(encode_sig)
#define racc_decode_sig SPARROW_(decode_sig)
#endif

#ifdef __cplusplus
extern "C" {
#endif

//  Encode public key "pk" to bytes "b". Return length in bytes.
size_t racc_encode_pk(uint8_t *b, const racc_pk_t *pk);

//  Decode a public key from "b" to "pk". Return length in bytes.
size_t racc_decode_pk(racc_pk_t *pk, const uint8_t *b);

//  Encode secret key "sk" to bytes "b". Return length in bytes.
size_t racc_encode_sk(uint8_t *b, const racc_sk_t *sk);

//  Decode a secret key from "b" to "sk". Return length in bytes.
size_t racc_decode_sk(racc_sk_t *sk, const uint8_t *b);

//  Encode ciphertext "ct" to "*b" of max "b_sz" bytes. Return length in
//  bytes or zero in case of overflow.
size_t racc_encode_ct(uint8_t *b, const racc_ciphertext_t *ct);

//  decode bytes "b" into ciphertext "ct". Return length in bytes.
size_t racc_encode_ct1(uint8_t *b, const racc_ciphertext_t *ct);
size_t racc_decode_ct(racc_ciphertext_t *ct, const uint8_t *b);

#ifdef __cplusplus
}
#endif

//  _SPARROW_SERIAL_H_
#endif
