//  test_aes1kt.c
//  Copyright (c) 2024 Sparrow KEM Team. See LICENSE.

//  === Simple AES implementation for test vector generation.
//  NOTE THAT THIS IS NOT CONSTANT TIME AND SHOULD NOT BE USED FOR PRODUCTION

/*
 *  Derived from optimised ANSI C code for the Rijndael cipher (now AES)
 *  Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
 *  Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>
 *  Paulo Barreto <paulo.barreto@terra.com.br>
 */

//  used only for test vector generation instead of the openssl aes
#ifndef NIST_KAT

#include "plat_local.h"
#include "test_aes1kt.h"

//  can handle non-aligned data

static const uint32_t ttab[256] = {
    0xA56363C6, 0x847C7CF8, 0x997777EE, 0x8D7B7BF6, 0x0DF2F2FF, 0xBD6B6BD6,
    0xB16F6FDE, 0x54C5C591, 0x50303060, 0x03010102, 0xA96767CE, 0x7D2B2B56,
    0x19FEFEE7, 0x62D7D7B5, 0xE6ABAB4D, 0x9A7676EC, 0x45CACA8F, 0x9D82821F,
    0x40C9C989, 0x877D7DFA, 0x15FAFAEF, 0xEB5959B2, 0xC947478E, 0x0BF0F0FB,
    0xECADAD41, 0x67D4D4B3, 0xFDA2A25F, 0xEAAFAF45, 0xBF9C9C23, 0xF7A4A453,
    0x967272E4, 0x5BC0C09B, 0xC2B7B775, 0x1CFDFDE1, 0xAE93933D, 0x6A26264C,
    0x5A36366C, 0x413F3F7E, 0x02F7F7F5, 0x4FCCCC83, 0x5C343468, 0xF4A5A551,
    0x34E5E5D1, 0x08F1F1F9, 0x937171E2, 0x73D8D8AB, 0x53313162, 0x3F15152A,
    0x0C040408, 0x52C7C795, 0x65232346, 0x5EC3C39D, 0x28181830, 0xA1969637,
    0x0F05050A, 0xB59A9A2F, 0x0907070E, 0x36121224, 0x9B80801B, 0x3DE2E2DF,
    0x26EBEBCD, 0x6927274E, 0xCDB2B27F, 0x9F7575EA, 0x1B090912, 0x9E83831D,
    0x742C2C58, 0x2E1A1A34, 0x2D1B1B36, 0xB26E6EDC, 0xEE5A5AB4, 0xFBA0A05B,
    0xF65252A4, 0x4D3B3B76, 0x61D6D6B7, 0xCEB3B37D, 0x7B292952, 0x3EE3E3DD,
    0x712F2F5E, 0x97848413, 0xF55353A6, 0x68D1D1B9, 0x00000000, 0x2CEDEDC1,
    0x60202040, 0x1FFCFCE3, 0xC8B1B179, 0xED5B5BB6, 0xBE6A6AD4, 0x46CBCB8D,
    0xD9BEBE67, 0x4B393972, 0xDE4A4A94, 0xD44C4C98, 0xE85858B0, 0x4ACFCF85,
    0x6BD0D0BB, 0x2AEFEFC5, 0xE5AAAA4F, 0x16FBFBED, 0xC5434386, 0xD74D4D9A,
    0x55333366, 0x94858511, 0xCF45458A, 0x10F9F9E9, 0x06020204, 0x817F7FFE,
    0xF05050A0, 0x443C3C78, 0xBA9F9F25, 0xE3A8A84B, 0xF35151A2, 0xFEA3A35D,
    0xC0404080, 0x8A8F8F05, 0xAD92923F, 0xBC9D9D21, 0x48383870, 0x04F5F5F1,
    0xDFBCBC63, 0xC1B6B677, 0x75DADAAF, 0x63212142, 0x30101020, 0x1AFFFFE5,
    0x0EF3F3FD, 0x6DD2D2BF, 0x4CCDCD81, 0x140C0C18, 0x35131326, 0x2FECECC3,
    0xE15F5FBE, 0xA2979735, 0xCC444488, 0x3917172E, 0x57C4C493, 0xF2A7A755,
    0x827E7EFC, 0x473D3D7A, 0xAC6464C8, 0xE75D5DBA, 0x2B191932, 0x957373E6,
    0xA06060C0, 0x98818119, 0xD14F4F9E, 0x7FDCDCA3, 0x66222244, 0x7E2A2A54,
    0xAB90903B, 0x8388880B, 0xCA46468C, 0x29EEEEC7, 0xD3B8B86B, 0x3C141428,
    0x79DEDEA7, 0xE25E5EBC, 0x1D0B0B16, 0x76DBDBAD, 0x3BE0E0DB, 0x56323264,
    0x4E3A3A74, 0x1E0A0A14, 0xDB494992, 0x0A06060C, 0x6C242448, 0xE45C5CB8,
    0x5DC2C29F, 0x6ED3D3BD, 0xEFACAC43, 0xA66262C4, 0xA8919139, 0xA4959531,
    0x37E4E4D3, 0x8B7979F2, 0x32E7E7D5, 0x43C8C88B, 0x5937376E, 0xB76D6DDA,
    0x8C8D8D01, 0x64D5D5B1, 0xD24E4E9C, 0xE0A9A949, 0xB46C6CD8, 0xFA5656AC,
    0x07F4F4F3, 0x25EAEACF, 0xAF6565CA, 0x8E7A7AF4, 0xE9AEAE47, 0x18080810,
    0xD5BABA6F, 0x887878F0, 0x6F25254A, 0x722E2E5C, 0x241C1C38, 0xF1A6A657,
    0xC7B4B473, 0x51C6C697, 0x23E8E8CB, 0x7CDDDDA1, 0x9C7474E8, 0x211F1F3E,
    0xDD4B4B96, 0xDCBDBD61, 0x868B8B0D, 0x858A8A0F, 0x907070E0, 0x423E3E7C,
    0xC4B5B571, 0xAA6666CC, 0xD8484890, 0x05030306, 0x01F6F6F7, 0x120E0E1C,
    0xA36161C2, 0x5F35356A, 0xF95757AE, 0xD0B9B969, 0x91868617, 0x58C1C199,
    0x271D1D3A, 0xB99E9E27, 0x38E1E1D9, 0x13F8F8EB, 0xB398982B, 0x33111122,
    0xBB6969D2, 0x70D9D9A9, 0x898E8E07, 0xA7949433, 0xB69B9B2D, 0x221E1E3C,
    0x92878715, 0x20E9E9C9, 0x49CECE87, 0xFF5555AA, 0x78282850, 0x7ADFDFA5,
    0x8F8C8C03, 0xF8A1A159, 0x80898909, 0x170D0D1A, 0xDABFBF65, 0x31E6E6D7,
    0xC6424284, 0xB86868D0, 0xC3414182, 0xB0999929, 0x772D2D5A, 0x110F0F1E,
    0xCBB0B07B, 0xFC5454A8, 0xD6BBBB6D, 0x3A16162C};

static const uint8_t sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B,
    0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
    0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
    0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
    0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
    0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC,
    0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14,
    0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
    0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F,
    0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
    0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
    0xB0, 0x54, 0xBB, 0x16};

static const uint8_t rcon[] = {0x01, 0x02, 0x04, 0x08, 0x10,
                               0x20, 0x40, 0x80, 0x1B, 0x36};

void aes1kt128_enc_key(uint32_t rk[44], const uint8_t key[16])
{
    int i;
    uint32_t temp;

    rk[0] = get32u_le(key);
    rk[1] = get32u_le(key + 4);
    rk[2] = get32u_le(key + 8);
    rk[3] = get32u_le(key + 12);

    for (i = 0; i < 10; i++) {
        temp = rk[3];
        rk[4] = ((uint32_t)rcon[i]) ^ rk[0] ^
                (((uint32_t)sbox[(temp >> 8) & 0xFF])) ^
                (((uint32_t)sbox[(temp >> 16) & 0xFF]) << 8) ^
                (((uint32_t)sbox[(temp >> 24) & 0xFF]) << 16) ^
                (((uint32_t)sbox[temp & 0xFF]) << 24);
        rk[5] = rk[1] ^ rk[4];
        rk[6] = rk[2] ^ rk[5];
        rk[7] = rk[3] ^ rk[6];
        rk += 4;
    }
}

void aes1kt192_enc_key(uint32_t rk[52], const uint8_t key[24])
{
    int i;
    uint32_t temp;

    rk[0] = get32u_le(key);
    rk[1] = get32u_le(key + 4);
    rk[2] = get32u_le(key + 8);
    rk[3] = get32u_le(key + 12);
    rk[4] = get32u_le(key + 16);
    rk[5] = get32u_le(key + 20);

    for (i = 0;;) {
        temp = rk[5];
        rk[6] = ((uint32_t)rcon[i]) ^ rk[0] ^
                (((uint32_t)sbox[(temp >> 8) & 0xFF])) ^
                (((uint32_t)sbox[(temp >> 16) & 0xFF]) << 8) ^
                (((uint32_t)sbox[(temp >> 24) & 0xFF]) << 16) ^
                (((uint32_t)sbox[temp & 0xFF]) << 24);
        rk[7] = rk[1] ^ rk[6];
        rk[8] = rk[2] ^ rk[7];
        rk[9] = rk[3] ^ rk[8];
        if (++i == 8)
            break;
        rk[10] = rk[4] ^ rk[9];
        rk[11] = rk[5] ^ rk[10];
        rk += 6;
    }
}

void aes1kt256_enc_key(uint32_t rk[60], const uint8_t key[32])
{
    int i;
    uint32_t temp;

    rk[0] = get32u_le(key);
    rk[1] = get32u_le(key + 4);
    rk[2] = get32u_le(key + 8);
    rk[3] = get32u_le(key + 12);
    rk[4] = get32u_le(key + 16);
    rk[5] = get32u_le(key + 20);
    rk[6] = get32u_le(key + 24);
    rk[7] = get32u_le(key + 28);

    for (i = 0;;) {
        temp = rk[7];
        rk[8] = ((uint32_t)rcon[i]) ^ rk[0] ^
                (((uint32_t)sbox[(temp >> 8) & 0xFF])) ^
                (((uint32_t)sbox[(temp >> 16) & 0xFF]) << 8) ^
                (((uint32_t)sbox[(temp >> 24) & 0xFF]) << 16) ^
                (((uint32_t)sbox[temp & 0xFF]) << 24);
        rk[9] = rk[1] ^ rk[8];
        rk[10] = rk[2] ^ rk[9];
        rk[11] = rk[3] ^ rk[10];
        if (++i == 7)
            break;
        temp = rk[11];
        rk[12] = rk[4] ^ (((uint32_t)sbox[temp & 0xFF])) ^
                 (((uint32_t)sbox[(temp >> 8) & 0xFF]) << 8) ^
                 (((uint32_t)sbox[(temp >> 16) & 0xFF]) << 16) ^
                 (((uint32_t)sbox[(temp >> 24) & 0xFF]) << 24);
        rk[13] = rk[5] ^ rk[12];
        rk[14] = rk[6] ^ rk[13];
        rk[15] = rk[7] ^ rk[14];
        rk += 8;
    }
}

void aes1k_enc_rounds(uint8_t ct[16], const uint8_t pt[16],
                        const uint32_t rk[], int nr)
{
    uint32_t s0, s1, s2, s3, t0, t1, t2, t3;
    int r;

    // get bytes -- use initial key
    s0 = get32u_le(pt) ^ rk[0];
    s1 = get32u_le(pt + 4) ^ rk[1];
    s2 = get32u_le(pt + 8) ^ rk[2];
    s3 = get32u_le(pt + 12) ^ rk[3];

    // nr - 1 full rounds:
    r = nr >> 1;
    for (;;) {
        t0 = ttab[s0 & 0xFF] ^ ror32(ttab[(s1 >> 8) & 0xFF], 24) ^
             ror32(ttab[(s2 >> 16) & 0xFF], 16) ^ ror32(ttab[s3 >> 24], 8) ^
             rk[4];
        t1 = ttab[s1 & 0xFF] ^ ror32(ttab[(s2 >> 8) & 0xFF], 24) ^
             ror32(ttab[(s3 >> 16) & 0xFF], 16) ^ ror32(ttab[s0 >> 24], 8) ^
             rk[5];
        t2 = ttab[s2 & 0xFF] ^ ror32(ttab[(s3 >> 8) & 0xFF], 24) ^
             ror32(ttab[(s0 >> 16) & 0xFF], 16) ^ ror32(ttab[s1 >> 24], 8) ^
             rk[6];
        t3 = ttab[s3 & 0xFF] ^ ror32(ttab[(s0 >> 8) & 0xFF], 24) ^
             ror32(ttab[(s1 >> 16) & 0xFF], 16) ^ ror32(ttab[s2 >> 24], 8) ^
             rk[7];

        rk += 8;
        if (--r == 0) {
            break;
        }
        s0 = ttab[t0 & 0xFF] ^ ror32(ttab[(t1 >> 8) & 0xFF], 24) ^
             ror32(ttab[(t2 >> 16) & 0xFF], 16) ^ ror32(ttab[t3 >> 24], 8) ^
             rk[0];
        s1 = ttab[t1 & 0xFF] ^ ror32(ttab[(t2 >> 8) & 0xFF], 24) ^
             ror32(ttab[(t3 >> 16) & 0xFF], 16) ^ ror32(ttab[t0 >> 24], 8) ^
             rk[1];
        s2 = ttab[t2 & 0xFF] ^ ror32(ttab[(t3 >> 8) & 0xFF], 24) ^
             ror32(ttab[(t0 >> 16) & 0xFF], 16) ^ ror32(ttab[t1 >> 24], 8) ^
             rk[2];
        s3 = ttab[t3 & 0xFF] ^ ror32(ttab[(t0 >> 8) & 0xFF], 24) ^
             ror32(ttab[(t1 >> 16) & 0xFF], 16) ^ ror32(ttab[t2 >> 24], 8) ^
             rk[3];
    }

    // last round, write it back

    s0 = rk[0] ^ (((uint32_t)sbox[t0 & 0xFF])) ^
         (((uint32_t)sbox[(t1 >> 8) & 0xFF]) << 8) ^
         (((uint32_t)sbox[(t2 >> 16) & 0xFF]) << 16) ^
         (((uint32_t)sbox[t3 >> 24]) << 24);

    s1 = rk[1] ^ (((uint32_t)sbox[t1 & 0xFF])) ^
         (((uint32_t)sbox[(t2 >> 8) & 0xFF]) << 8) ^
         (((uint32_t)sbox[(t3 >> 16) & 0xFF]) << 16) ^
         (((uint32_t)sbox[t0 >> 24]) << 24);

    s2 = rk[2] ^ (((uint32_t)sbox[t2 & 0xFF])) ^
         (((uint32_t)sbox[(t3 >> 8) & 0xFF]) << 8) ^
         (((uint32_t)sbox[(t0 >> 16) & 0xFF]) << 16) ^
         (((uint32_t)sbox[t1 >> 24]) << 24);

    s3 = rk[3] ^ (((uint32_t)sbox[t3 & 0xFF])) ^
         (((uint32_t)sbox[(t0 >> 8) & 0xFF]) << 8) ^
         (((uint32_t)sbox[(t1 >> 16) & 0xFF]) << 16) ^
         (((uint32_t)sbox[t2 >> 24]) << 24);

    put32u_le(ct, s0);
    put32u_le(ct + 4, s1);
    put32u_le(ct + 8, s2);
    put32u_le(ct + 12, s3);
}

//  just key length varies

void aes1kt128_enc_ecb(uint8_t ct[16], const uint8_t pt[16],
                    const uint32_t rk[AES128_RK_WORDS])
{
    aes1k_enc_rounds(ct, pt, rk, AES128_ROUNDS);
}

void aes1kt192_enc_ecb(uint8_t ct[16], const uint8_t pt[16],
                    const uint32_t rk[AES192_RK_WORDS])
{
    aes1k_enc_rounds(ct, pt, rk, AES192_ROUNDS);
}

void aes1kt256_enc_ecb(uint8_t ct[16], const uint8_t pt[16],
                    const uint32_t rk[AES256_RK_WORDS])
{
    aes1k_enc_rounds(ct, pt, rk, AES256_ROUNDS);
}

//  NIST_KAT
#endif
