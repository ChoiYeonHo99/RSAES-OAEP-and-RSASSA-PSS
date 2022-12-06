/*
 * Copyright 2020-2022. Heekuck Oh, all rights reserved
 * 이 프로그램은 한양대학교 ERICA 소프트웨어학부 재학생을 위한 교육용으로 제작되었다.
 */
#ifdef __linux__
#include <bsd/stdlib.h>
#elif __APPLE__
#include <stdlib.h>
#else
#include <stdlib.h>
#endif
#include <string.h>
#include <gmp.h>
#include "pkcs.h"
#include "sha2.h"

/*
 * rsa_generate_key() - generates RSA keys e, d and n in octet strings.
 * If mode = 0, then e = 65537 is used. Otherwise e will be randomly selected.
 * Carmichael's totient function Lambda(n) is used.
 */
void rsa_generate_key(void *_e, void *_d, void *_n, int mode)
{
    mpz_t p, q, lambda, e, d, n, gcd;
    gmp_randstate_t state;
    
    /*
     * Initialize mpz variables
     */
    mpz_inits(p, q, lambda, e, d, n, gcd, NULL);
    gmp_randinit_default(state);
    gmp_randseed_ui(state, arc4random());
    /*
     * Generate prime p and q such that 2^(RSAKEYSIZE-1) <= p*q < 2^RSAKEYSIZE
     */
    do {
        do {
            mpz_urandomb(p, state, RSAKEYSIZE/2);
            mpz_setbit(p, 0);
            mpz_setbit(p, RSAKEYSIZE/2-1);
        } while (mpz_probab_prime_p(p, 50) == 0);
        do {
            mpz_urandomb(q, state, RSAKEYSIZE/2);
            mpz_setbit(q, 0);
            mpz_setbit(q, RSAKEYSIZE/2-1);
        } while (mpz_probab_prime_p(q, 50) == 0);
        mpz_mul(n, p, q);
    } while (!mpz_tstbit(n, RSAKEYSIZE-1));
    /*
     * Generate e and d using Lambda(n)
     */
    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_lcm(lambda, p, q);
    if (mode == 0)
        mpz_set_ui(e, 65537);
    else do {
        mpz_urandomb(e, state, RSAKEYSIZE);
        mpz_gcd(gcd, e, lambda);
    } while (mpz_cmp(e, lambda) >= 0 || mpz_cmp_ui(gcd, 1) != 0);
    mpz_invert(d, e, lambda);
    /*
     * Convert mpz_t values into octet strings
     */
    mpz_export(_e, NULL, 1, RSAKEYSIZE/8, 1, 0, e);
    mpz_export(_d, NULL, 1, RSAKEYSIZE/8, 1, 0, d);
    mpz_export(_n, NULL, 1, RSAKEYSIZE/8, 1, 0, n);
    /*
     * Free the space occupied by mpz variables
     */
    mpz_clears(p, q, lambda, e, d, n, gcd, NULL);
}

/*
 * rsa_cipher() - compute m^k mod n
 * If m >= n then returns PKCS_MSG_OUT_OF_RANGE, otherwise returns 0 for success.
 */
static int rsa_cipher(void *_m, const void *_k, const void *_n)
{
    mpz_t m, k, n;
    
    /*
     * Initialize mpz variables
     */
    mpz_inits(m, k, n, NULL);
    /*
     * Convert big-endian octets into mpz_t values
     */
    mpz_import(m, RSAKEYSIZE/8, 1, 1, 1, 0, _m);
    mpz_import(k, RSAKEYSIZE/8, 1, 1, 1, 0, _k);
    mpz_import(n, RSAKEYSIZE/8, 1, 1, 1, 0, _n);
    /*
     * Compute m^k mod n
     */
    if (mpz_cmp(m, n) >= 0) {
        mpz_clears(m, k, n, NULL);
        return PKCS_MSG_OUT_OF_RANGE;
    }
    mpz_powm(m, m, k, n);
    /*
     * Convert mpz_t m into the octet string _m
     */
    mpz_export(_m, NULL, 1, RSAKEYSIZE/8, 1, 0, m);
    /*
     * Free the space occupied by mpz variables
     */
    mpz_clears(m, k, n, NULL);
    return 0;
}

typedef struct {
    size_t hashLen;
    size_t messageLimitLen;
    void (*hashFunction)(const unsigned char *message, unsigned int length, unsigned char *digit);
} hashInfo;

/** @brief Hash 관련 정보 봔환
 *  @param sha2_ndx : 사용할 SHA2 hash
 *  @result : hashInfo(hashLen : hash 길이 , messageLimitLen : 입력 메세지 최대 길이_2의 지수승)
 */
static hashInfo getHashInfo(const int sha2_ndx){
    switch(sha2_ndx){
        case SHA224:
            return (hashInfo){SHA224_DIGEST_SIZE, 64, sha224};
            break;
        case SHA256:
            return (hashInfo){SHA256_DIGEST_SIZE, 64, sha256};
            break;
        case SHA384:
            return (hashInfo){SHA384_DIGEST_SIZE, 128, sha384};
            break;
        case SHA512:
            return (hashInfo){SHA512_DIGEST_SIZE, 128, sha512};
            break;
        case SHA512_224:
            return (hashInfo){SHA224_DIGEST_SIZE, 128, sha512_224};
            break;
        case SHA512_256:
            return (hashInfo){SHA256_DIGEST_SIZE, 128, sha512_256};
            break;
        default:
            return (hashInfo){-1, 0, sha224};
            break;
    }
}

static int i2osp(unsigned char *str, uint64_t x, size_t xlen) {
    int tmp;
    if (x >> (8 * xlen) != 0) {
        printf("integer too large\n");
        return 1;
    }

    for (int i = 1; i <= xlen; i++) {
        tmp = 255 & x;
        str[xlen - i] = (uint8_t)tmp;
        x = x >> 8;
    }

    return 0;
}

static int mgf1(unsigned char *mgf, void *mgfseed, size_t seedLen, size_t maskLen, int sha2_ndx) {
    // set hLen
    size_t hlen = 0;
    hashInfo hi = getHashInfo(sha2_ndx);
    hlen = hi.hashLen;
    
    // check "mask too long" error
    if ((maskLen >> 32) > hlen ) {
        return PKCS_HASH_TOO_LONG;
    }

    // set ceil(maskLen / hLen)
    int l = (maskLen - maskLen % hlen) / hlen;
    for (int i = 0; i <= l; i++) {
        unsigned char c[4];
        unsigned char h[seedLen + 4], tmp[hlen];
        // C = I2OSP(i, 4)
        i2osp(c, i, 4);

        // mgfSeed || C
        memcpy(h, mgfseed, seedLen);
        memcpy(h+seedLen, c, 4);
        
        //Hash(mgfSeed || C)
        hi.hashFunction(h, seedLen+4, tmp);

        if (i != l) {
            // T = T || Hash(mgfSeed || C)
            memcpy(mgf+(i*hlen),tmp,hlen);
        }
        else {
            // maskLen 초과부분 잘라주기
            memcpy(mgf+(i*hlen),tmp,maskLen % hlen);
        }
    }
    return 0;
}

/*
 * rsaes_oaep_encrypt() - RSA encrytion with the EME-OAEP encoding method
 * 길이가 len 바이트인 메시지 m을 공개키 (e,n)으로 암호화한 결과를 c에 저장한다.
 * label은 데이터를 식별하기 위한 라벨 문자열로 NULL을 입력하여 생략할 수 있다.
 * sha2_ndx는 사용할 SHA-2 해시함수 색인 값으로 SHA224, SHA256, SHA384, SHA512,
 * SHA512_224, SHA512_256 중에서 선택한다. c의 크기는 RSAKEYSIZE와 같아야 한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int rsaes_oaep_encrypt(const void *m, size_t mLen, const void *label, const void *e, const void *n, void *c, int sha2_ndx) {
    // PKCS_LABEL_TOO_LONG – 라벨의 길이가 너무 길어 한도를 초과함 [RSAES-OAEP]
    if (strlen(label) >= 0x1fffffffffffffffLL)
        return PKCS_LABEL_TOO_LONG;
    
    size_t hLen;
    unsigned char *lHash;
    hashInfo hi = getHashInfo(sha2_ndx);
    
    // sha2_ndx에 따른 hLen을 결정하고 label을 Hash하여 lHash에 저장한다
    hLen = hi.hashLen;
    lHash = malloc(sizeof(unsigned char) * hLen);

    hi.hashFunction(label, strlen(label), lHash);

    // PKCS_MSG_TOO_LONG – 입력 메시지가 너무 길어 한도를 초과함
    if (mLen > RSAKEYSIZE / 8 - 2 * hLen - 2)
        return PKCS_MSG_TOO_LONG;

    // RSAKEYSIZE, hLen, mLen에 따른 PaddingStirng을 생선한다
    size_t psLen = RSAKEYSIZE / 8 - 2 - 2 * hLen - mLen;

    unsigned char *PaddingString = calloc(psLen, sizeof(unsigned char));


    // hLen, mLen, psLen에 따른 DataBlock을 생성한다
    size_t dbLen = hLen + psLen + 1 + mLen;
    unsigned char *DataBlock = malloc(sizeof(unsigned char) * dbLen);

    // DataBlock에 순서대로 lHash, PaddingStirng, 0x01, Message를 연결한다
    unsigned char temp[1] = {0x01};
    memcpy(DataBlock, lHash, hLen);
    memcpy(DataBlock + hLen, PaddingString, psLen);
    memcpy(DataBlock + hLen + psLen, temp, 1);
    memcpy(DataBlock + hLen + psLen + 1, m, mLen);

    // 난수 byte 문자열 seed를 생성한다
    unsigned char *seed = malloc(sizeof(unsigned char) * hLen);
    arc4random_buf(seed, hLen);

    // seed를 MGF에 넣어서 dbMask를 생선한다
    unsigned char *dbMask = malloc(sizeof(unsigned char) * dbLen);
    mgf1(dbMask, seed, hLen, dbLen, sha2_ndx);

    // mgf1(dbMask) XOR DataBlock으로 MaskedDataBlock을 생성한다
    unsigned char *MaskedDataBlock = malloc(sizeof(unsigned char) * dbLen);
    for (int i = 0; i < dbLen; i++) {
        MaskedDataBlock[i] = dbMask[i] ^ DataBlock[i];
    }

    // MaskedDataBlock을 MGF에 넣어서 seedMask를 생선한다
    unsigned char *seedMask = malloc(sizeof(unsigned char) * hLen);
    mgf1(seedMask, MaskedDataBlock, dbLen, hLen, sha2_ndx);

    // mgf2(seedMask) XOR seed로 MaskedSeed을 생성한다
    unsigned char *MaskedSeed = malloc(sizeof(unsigned char) * hLen);
    for (int i = 0; i < hLen; i++) {
        MaskedSeed[i] = seedMask[i] ^ seed[i];
    };

    // EncodedMessage에 순서대로 0x00, MaskedSeed, MaskedDataBlock을 연결한다
    unsigned char *EncodedMessage = malloc(sizeof(unsigned char) * RSAKEYSIZE / 8);
    temp[0] = 0x00;
    memcpy(EncodedMessage, temp, 1);
    memcpy(EncodedMessage + 1, MaskedSeed, hLen);
    memcpy(EncodedMessage + 1 + hLen, MaskedDataBlock, dbLen);

    // EncodedMessage를 rsa로 암호화한다 
    int rsa_result = rsa_cipher(EncodedMessage, e, n);
    if(rsa_result != 0)
        return rsa_result;

    // 암호화된 EncodedMessage를 c에 저장한다
    memcpy(c, EncodedMessage, (RSAKEYSIZE / 8));

    // 사용했던 string들에 할당했던 memory를 모두 free해준다
    free(lHash);
    free(PaddingString);
    free(DataBlock);
    free(seed);
    free(dbMask);
    free(seedMask);
    free(MaskedDataBlock);
    free(MaskedSeed);
    free(EncodedMessage);

    return 0;
}
/*
 * rsaes_oaep_decrypt() - RSA decrytion with the EME-OAEP encoding method
 * 암호문 c를 개인키 (d,n)을 사용하여 원본 메시지 m과 길이 len을 회복한다.
 * label과 sha2_ndx는 암호화할 때 사용한 것과 일치해야 한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
/** @brief RSAES_OAEP 복호화
 *  @param m : 복호화된 메세지
 *  @param mLen : 복호화된 메세지 길이
 *  @param label : RSAES_OAEP에서 사용되는 label
 *  @param d : RSA키 개인 키
 *  @param n : RSA키 modulo 값 n
 *  @param c : 복호화 대상 암호문
 *  @param sha2_ndx : 사용할 sha2 hash 버전
 *  @result : 복호화 성공시 0, 실패 시 정의된 에러 코드를 반환한다.
 */
int rsaes_oaep_decrypt(void *m, size_t *mLen, const void *label, const void *d, const void *n, const void *c, int sha2_ndx){
    hashInfo hi = getHashInfo(sha2_ndx);

    if(strlen(label) >= 0x1fffffffffffffffLL)
        return PKCS_LABEL_TOO_LONG; // 라벨 길이 제한 초과
    
    //RSA 복호화
    unsigned char *encodedMessage = malloc(sizeof(unsigned char) * (RSAKEYSIZE/8));
    memcpy(encodedMessage, c, sizeof(unsigned char) * (RSAKEYSIZE/8));

    int rsa_result = rsa_cipher(encodedMessage, d, n);
    if(rsa_result != 0)
        return rsa_result;

    if(encodedMessage[0] != 0x00)
        return PKCS_INITIAL_NONZERO; // encoded message의 첫번째 byte가 0이 아니다.

    // XOR 처리 - 원래의 seed, dataBlock 복원하기
    unsigned char *maskedSeed = malloc(sizeof(unsigned char) * hi.hashLen);
    memcpy(maskedSeed, encodedMessage + 1, sizeof(unsigned char) * hi.hashLen);

    unsigned char *maskedDataBlock = malloc(sizeof(unsigned char) * (RSAKEYSIZE/8 - hi.hashLen - 1));
    memcpy(maskedDataBlock, encodedMessage + hi.hashLen + 1, sizeof(unsigned char) * (RSAKEYSIZE/8 - hi.hashLen - 1));

    unsigned char *seed = malloc(sizeof(unsigned char) * hi.hashLen);
    unsigned char *dataBlock = malloc(sizeof(unsigned char) * (RSAKEYSIZE/8 - hi.hashLen - 1));
    mgf1(seed, maskedDataBlock, RSAKEYSIZE/8 - hi.hashLen - 1, hi.hashLen, sha2_ndx);

    for (int i = 0; i < hi.hashLen; ++i)
        seed[i] ^= maskedSeed[i];

    mgf1(dataBlock, seed, hi.hashLen, RSAKEYSIZE/8 - hi.hashLen - 1, sha2_ndx);

    for (int i = 0; i < RSAKEYSIZE/8 - hi.hashLen - 1; ++i)
        dataBlock[i] ^= maskedDataBlock[i];

    // 원래의 message 복원하기
    // ... Hash(label) 확인
    unsigned char *labelHash = malloc(sizeof(unsigned char) * hi.hashLen);
    memcpy(labelHash, dataBlock, sizeof(unsigned char) * hi.hashLen);

    unsigned char *labelHash_inp = malloc(sizeof(unsigned char) * hi.hashLen);
    hi.hashFunction(label, strlen(label), labelHash_inp);

    if(memcmp(labelHash, labelHash_inp, hi.hashLen) != 0)
        return PKCS_HASH_MISMATCH; // label hash가 일치하지 않음

    // ... padingString 확인
    size_t ptr = hi.hashLen;
    for(;ptr < RSAKEYSIZE/8 - hi.hashLen - 1 && dataBlock[ptr] == 0x00; ++ptr);
    unsigned char divider = ptr < RSAKEYSIZE/8 - hi.hashLen - 1 ? dataBlock[ptr] : 0x00;

    if(divider != 0x01)
        return PKCS_INVALID_PS; // paddingString 뒤에 오는 값이 0x01이 아님

    // ... message 확인 및 복호화
    *mLen = RSAKEYSIZE/8 - hi.hashLen - 1 - ++ptr;
    memcpy(m, dataBlock + ptr, sizeof(char) * *mLen);

    // 동적 메모리 할당 해제
    free(encodedMessage);
    free(maskedSeed);
    free(maskedDataBlock);
    free(seed);
    free(dataBlock);
    free(labelHash);
    free(labelHash_inp);
    return 0;
}

/*
 * rsassa_pss_sign - RSA Signature Scheme with Appendix
 * 길이가 len 바이트인 메시지 m을 개인키 (d,n)으로 서명한 결과를 s에 저장한다.
 * s의 크기는 RSAKEYSIZE와 같아야 한다. 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
static int emsa_pss_encode(const void *m, size_t mLen, unsigned char *encodedMessage, int sha2_ndx){
    int emLen = RSAKEYSIZE / 8;
    unsigned char *H;
    
    //step 2
    hashInfo hi = getHashInfo(sha2_ndx);
    int hLen = hi.hashLen;
    
    //step3
    if(emLen < hLen * 2 + 2) return PKCS_HASH_TOO_LONG;
    
    unsigned char *mHash = malloc(sizeof(unsigned char) * hi.hashLen);
    hi.hashFunction(m, strlen(m), mHash);
    
    //step1
    if(mLen >= 0x1fffffffffffffffLL) return PKCS_MSG_TOO_LONG;
    
    //salt rand, sLen = hLen
    //step 4
    unsigned char *salt = malloc(sizeof(unsigned char) * hLen);
    arc4random_buf(salt, hLen);
    
    //step 5 mdot
    size_t mdotLen = 8 + hLen * 2;
    unsigned char *mdot = malloc(sizeof(unsigned char) * mdotLen);
    unsigned char temp[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(mdot, temp, 8);
    memcpy(mdot + 8, mHash, hLen);
    memcpy(mdot + 8 + hLen, salt, hLen);

    //step 6 ***
    H = malloc(sizeof(unsigned char) * hLen);
    hi.hashFunction(mdot, mdotLen, H);
    
    //step 7
    size_t dbLen = emLen - hLen - 1;
    size_t psLen = dbLen - hLen - 1;
    unsigned char *ps = calloc(psLen, sizeof(unsigned char)); //fill 0
    
    //DB
    //step 8
    unsigned char *DB = malloc(sizeof(unsigned char) * dbLen);
    unsigned char tmp[1] = {0x01};
    memcpy(DB, ps, psLen);
    memcpy(DB + psLen, tmp, 1);
    memcpy(DB + psLen + 1, salt, hLen);
    
    //step 9
    unsigned char *dbMask = malloc(sizeof(unsigned char) * dbLen);
    mgf1(dbMask, H, hLen, dbLen, sha2_ndx);

    //step 10
    unsigned char *maskedDB = malloc(sizeof(unsigned char) * dbLen);
    for (int i = 0; i < dbLen; i++) {
        maskedDB[i] = DB[i] ^ dbMask[i];
    }
    
    //step 11 & 12
    unsigned char tmp1[1] = {0xbc};
    memcpy(encodedMessage, maskedDB, dbLen);
    memcpy(encodedMessage + dbLen, H, hLen);
    memcpy(encodedMessage + dbLen + hLen, tmp1, 1);

    if ((encodedMessage[0] & 0x80) >> 7 == 1)
       encodedMessage[0] ^= 0x80;
    
    free(mHash);
    free(H);
    free(ps);
    free(dbMask);
    free(maskedDB);
    free(mdot);
    free(salt);

    return 0;
}

/*
 * rsassa_pss_sign - RSA Signature Scheme with Appendix
 * 길이가 len 바이트인 메시지 m을 개인키 (d,n)으로 서명한 결과를 s에 저장한다.
 * s의 크기는 RSAKEYSIZE와 같아야 한다. 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int rsassa_pss_sign(const void *m, size_t mLen, const void *d, const void *n, void *s, int sha2_ndx){
    unsigned char *encodedMessage = malloc(sizeof(unsigned char) * (RSAKEYSIZE / 8));
    int eps_result = emsa_pss_encode(m, mLen, encodedMessage, sha2_ndx);
    if(eps_result != 0)
        return eps_result; // encode message 생성 과정에 오류가 있으면 해당 오류를 반환한다.
    
    rsa_cipher(encodedMessage, d, n);
    
    memcpy(s, encodedMessage, RSAKEYSIZE / 8);

    return 0;
}

/*
 * rsassa_pss_verify - RSA Signature Scheme with Appendix
 * 길이가 len 바이트인 메시지 m에 대한 서명이 s가 맞는지 공개키 (e,n)으로 검증한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
 

int rsassa_pss_verify(const void *m, size_t mLen, const void *e, const void *n, const void *s, int sha2_ndx){
    size_t hLen, sLen;
    unsigned char *mHash, *Hdot;

    //step 1
    if (mLen >= 0x1fffffffffffffffLL) return PKCS_MSG_TOO_LONG;
    
    unsigned char *encodedMessage = malloc(sizeof(unsigned char) * (RSAKEYSIZE / 8));
    memcpy(encodedMessage, s, RSAKEYSIZE / 8);
    int rsa_ret = rsa_cipher(encodedMessage, e, n);
    if(rsa_ret)
        return rsa_ret;

    //step 2
    hashInfo hi = getHashInfo(sha2_ndx);
    hLen = hi.hashLen;
    mHash = malloc(sizeof(unsigned char) * hLen);
    hi.hashFunction(m, strlen(m), mHash);
    sLen = hLen;
    
    //step 3
    if (RSAKEYSIZE < hLen * 2 + 2) return PKCS_HASH_TOO_LONG;
    
    //step 4
    if (encodedMessage[RSAKEYSIZE / 8 - 1] != 0xbc) return PKCS_INVALID_LAST;
    
    //step 5
    size_t emLen = RSAKEYSIZE / 8;
    size_t dbLen = emLen - hLen - 1;

    unsigned char *maskedDB = malloc(sizeof(unsigned char) * (dbLen));
    for (int i = 0; i < dbLen; i++) {
        maskedDB[i] = encodedMessage[i];
    }
    unsigned char *H = malloc(sizeof(unsigned char) * (hLen));
    for (int i = 0; i < hLen; i++) {
        H[i] = encodedMessage[dbLen + i];
    }
    
    //step 6 *** leftmost (RSAKEYSIZE - embits) * 8bits = 0x00
    if ((encodedMessage[0] & 0x80) >> 7 != 0)
       return PKCS_INVALID_INIT;
    
    //step 7
    unsigned char *dbMask = malloc(sizeof(unsigned char) * dbLen);
    mgf1(dbMask, H, hLen, dbLen, sha2_ndx);
    
    //step 8
    unsigned char *DB = malloc(sizeof(unsigned char) * dbLen);
    for (int i = 0; i < dbLen; i++) {
        DB[i] = maskedDB[i] ^ dbMask[i];
    }
    
    //step 9 *** leftmost (8 * RSAKEYSIZE - embits = 0) = 0
    if ((DB[0] & 0x80) >> 7 == 1)
        DB[0] ^= 0x80;
    
    //step 10 
    for (int i = 0; i < (emLen - hLen - sLen - 2); i++) {
        if (DB[i] != 0x00) return PKCS_INVALID_PD2;
    }
    if(DB[emLen - hLen - sLen - 2] != 0x01) return PKCS_INVALID_PD2;
    
    //step 11
    unsigned char *salt = malloc(sizeof(unsigned char) * sLen);
    for (int i = 0; i < sLen; i++) {
        salt[i] = DB[dbLen - sLen + i];
    }    
    
    //step 12
    unsigned char *mdot = malloc(sizeof(unsigned char) * (hLen + sLen + 8));
    unsigned char tmp[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(mdot, tmp, 8);
    memcpy(mdot + 8, mHash, hLen);
    memcpy(mdot + 8 + hLen, salt, sLen);
    
    //step 13 *** Hdot type error
    Hdot = malloc(sizeof(unsigned char) * hLen);
    hi.hashFunction(mdot, 8 + hLen + sLen, Hdot);
    
    //step 14
    if(memcmp(Hdot, H, hLen))
        return PKCS_HASH_MISMATCH;
    
    return 0;
}