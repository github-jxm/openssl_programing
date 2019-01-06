/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h> 

#include "internal/sm2.h"

#include "generate_key.c"

static RAND_METHOD fake_rand;
static const RAND_METHOD *saved_rand;

static uint8_t *fake_rand_bytes = NULL;
static size_t fake_rand_bytes_offset = 0;
static size_t fake_rand_size = 0;

static EC_GROUP *create_EC_group(const char *p_hex, const char *a_hex,
                                 const char *b_hex, const char *x_hex,
                                 const char *y_hex, const char *order_hex,
                                 const char *cof_hex)
{
    BIGNUM *p = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *g_x = NULL;
    BIGNUM *g_y = NULL;
    BIGNUM *order = NULL;
    BIGNUM *cof = NULL;
    EC_POINT *generator = NULL;
    EC_GROUP *group = NULL;

    BN_hex2bn(&p, p_hex);
    BN_hex2bn(&a, a_hex);
    BN_hex2bn(&b, b_hex);

    group = EC_GROUP_new_curve_GFp(p, a, b, NULL);

    generator = EC_POINT_new(group);

    BN_hex2bn(&g_x, x_hex);
    BN_hex2bn(&g_y, y_hex);
    //说明：设置素数域椭圆曲线上点point的几何坐标；
    EC_POINT_set_affine_coordinates(group, generator, g_x, g_y, NULL); 

    BN_hex2bn(&order, order_hex);
    BN_hex2bn(&cof, cof_hex);
    //说明：设置椭圆曲线的基G ；generator、order和cofactor为输入参数；
    EC_GROUP_set_generator(group, generator, order, cof);

    int ok = 1;
done:
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(g_x);
    BN_free(g_y);
    EC_POINT_free(generator);
    BN_free(order);
    BN_free(cof);
    if (!ok) {
        EC_GROUP_free(group);
        group = NULL;
    }

    return group;
}

static int test_sm2_crypt(const EC_GROUP *group,
                          const EVP_MD *digest,
                          const char *privkey_hex,
                          const char *message)
{

    const size_t msg_len = strlen(message);
    BIGNUM *priv = NULL;
    EC_KEY *key = NULL;
    EC_POINT *pt = NULL;
    size_t ctext_len = 0;
    size_t ptext_len = 0;
    uint8_t *ctext = NULL;
    uint8_t *recovered = NULL;
    size_t recovered_len = msg_len;
    int rc = 0;

    unsigned char pubKey[256 + 1] = {0};
    unsigned char *ptrPubKey = pubKey;
    unsigned int pubKeyLen = 0;


    unsigned char priKey[256 + 1] = {0};
    unsigned char *ptrPriKey = priKey;
    unsigned int priKeyLen = 0;

    BIGNUM * ret1 = NULL;


    int i;
    // init bio_out
    BIO *bio_out;
    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);


    // set private key  
    BN_hex2bn(&priv, privkey_hex);

    key = EC_KEY_new();
    EC_KEY_set_group(key, group);
    EC_KEY_set_private_key(key, priv);

    // set public key  
    pt = EC_POINT_new(group);
    EC_POINT_mul(group, pt, priv, NULL, NULL, NULL);
    EC_KEY_set_public_key(key, pt);

    // get ciphertext size
    sm2_ciphertext_size(key, digest, msg_len, &ctext_len); //  密文长度

    ctext = OPENSSL_zalloc(ctext_len);
    BIO_printf(bio_out,"sm2_encrypt: : %s \n", message);
    // get pubkey char
    //
    //if ( NULL ==  o2i_ECPublicKey(key,&ptrPubKey,pubKeyLen) goto err;
    pubKeyLen = i2o_ECPublicKey(key,&ptrPubKey);
    BIO_printf(bio_out,"----------- pubKey :  Len = %d ---------------\n" , pubKeyLen);

    ret1=BN_new();
    //unsigned char *c = "04435b39cca8f3b508c1488afc67be491a0f7ba07e581a0e4849a5cf70628a7e0a75ddba78f15feecb4c7895e2c1cdf5fe01debb2cdbadf45399ccf77bba076a42";
    //i = BN_hex2bn(&ret1, c); // 16进制字符串 转换 bn
    //i = BN_bn2bin(ret1, ptrPubKey);
    ptrPubKey = pubKey;
    ret1=BN_bin2bn(ptrPubKey,pubKeyLen, ret1);
    //BN_print(bio_out, ret1);
    //BIO_printf(bio_out,"\n----------------------------------------------\n");

    // conver to hex_str
    unsigned char *str_hex = NULL;
    str_hex = BN_bn2hex(ret1); 
    BIO_printf(bio_out,"%s\n",str_hex);
    OPENSSL_free(str_hex);
    BIO_printf(bio_out,"\n----------------------------------------------\n");


    /*
     *  rv = EC_KEY_set_private_key(key,d)
     *  if (rv !=1 ) goto err;
     *  keylenth = ECDSA_size(key)
     *
     *  
     *  PEM_read_ECPrivateKey(pfile,&key,NULL,NULL)
	    */

    const BIGNUM *d = NULL; 	
    
    d = EC_KEY_get0_private_key(key);
    if ( NULL == d ){
    	goto done;
    }
    priKeyLen = BN_bn2bin(d,priKey);

    BIO_printf(bio_out,"----------- priKey :  Len = %d ---------------\n" , priKeyLen);
    ptrPriKey = priKey;
    ret1=BN_bin2bn(ptrPriKey,priKeyLen, ret1);
    //BN_print(bio_out, ret1);
    //BIO_printf(bio_out,"\n----------------------------------------------\n");

    // conver to hex_str
    str_hex = BN_bn2hex(ret1); 
    BIO_printf(bio_out,"%s\n",str_hex);
    OPENSSL_free(str_hex);
    BIO_printf(bio_out,"\n----------------------------------------------\n");

    //  encrypt
    sm2_encrypt(key, digest, (const uint8_t *)message, msg_len, ctext, &ctext_len);

    sm2_plaintext_size(key, digest, ctext_len, &ptext_len);
    //if (!TEST_true(sm2_plaintext_size(key, digest, ctext_len, &ptext_len))
    //       || !TEST_int_eq(ptext_len, msg_len))
    //    goto done;
    //

    BIO_printf(bio_out,"----------- sm2_encrypt :  Len = %zu ---------------\n" , ctext_len);
    ret1=BN_bin2bn(ctext,ctext_len, ret1);
    BN_print(bio_out, ret1);
    BIO_printf(bio_out,"\n----------------------------------------------\n");

    recovered = OPENSSL_zalloc(ptext_len);


    //unsigned char * encrypt_hex_str = "307B02207B639E4FC8E527EF04BF97E65D1BB0DBFD949B927FF22329C16E623BA64AB2D8022048AF7B79CC7CA037B0E6016351300AA725BFBC5C22B64369EB32D66ECBD535120420F10A620B4B0B8D749863CEEFCEAAA718E0312EA8AF792719EA4A858E5BB2CB560413E1FF7988ED5E62DC9CBE190DF6C81C04828F71";
   // unsigned char * encrypt_hex_str = "307C022100D566F1CCB7429CD0D6FF9BD44747026FBD52200EEA0C01A59C50C03863D75B10022006A3B88D8090C548A74"
   //         "A9BB38C890B772777F081CDA119AD0D4507826C2A28D70420604CC72456C11270D1C4C4251FAB60C"
   //         "26D54F26BC6EBC9F8F14AB91F31288BA204135AAC5420019F08BC630912CB3563730F95F19B";

   // BN_hex2bn(&ret1, encrypt_hex_str); // 16进制字符串 转换 bn
   // 
   // BN_print(bio_out, ret1);
   // BIO_printf(bio_out, "\n");
   // ctext_len=BN_bn2bin(ret1,ctext);

    // decrypt
    sm2_decrypt(key, digest, ctext, ctext_len, recovered, &recovered_len);

    BIO_printf(bio_out,"sm2_decrypt: : %s \n", recovered); //|| !TEST_int_eq(recovered_len, msg_len)
            //|| !TEST_mem_eq(recovered, recovered_len, message, msg_len))
    rc = 1;
 done:

    BIO_free(bio_out);
    BN_free(priv);
    EC_POINT_free(pt);
    OPENSSL_free(ctext);
    OPENSSL_free(recovered);
    //OPENSSL_free(expected);
    EC_KEY_free(key);
    return rc;
}

static int sm2_crypt_test(void)
{
    int testresult = 0;

    printf("\n---- create_EC_group ----\n");
//  EC_GROUP *test_group =
//        create_EC_group ("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",
//			 "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498",
//			 "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A",
//			 "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D",
//			 "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2",
//			 "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",
//			 "1");
//
    /* 选取一种椭圆曲线 */
    /* 根据选择的椭圆曲线生成密钥参数 group */
    EC_GROUP *test_group=EC_GROUP_new_by_curve_name(NID_sm2);
    if(test_group==NULL) {
            printf("EC_GROUP_new_by_curve_name err!\n");
            return -1;
    }

    unsigned char privKey_str[1024];
    unsigned char pubKey_str[1024];
    sm2_generate_key(privKey_str,pubKey_str);


    printf("\n---- test sm2 crypt  EVP_sm3----\n");
    if (!test_sm2_crypt( test_group, EVP_sm3(),
		    privKey_str,
		    "encryption standard")
	)
        goto done;

    //printf("\n---- test sm2 crypt  EVP_sm3----\n");
    //if (!test_sm2_crypt( test_group, EVP_sm3(),
    //    	    "1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0",
    //    	    "encryption standard")
    //    )
    //    goto done;

    //printf("\n---- test sm2 crypt  EVP_sha256----\n");
    /* Same test as above except using SHA-256 instead of SM3 */
    //if (!test_sm2_crypt(
    //        test_group,
    //        EVP_sha256(),
    //        "1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0",
    //        "encryption standard"
    //        ))
    //    goto done;

    testresult = 1;
 done:
    EC_GROUP_free(test_group);

    return testresult;
}


int main()
{
         return sm2_crypt_test();
}

