/*
    sarp -- criptographic functions

    Copyright (C) 2002  ALoR <alor@blackhats.it>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

*/

#include <sarp_main.h>
#include <sarp_crypto.h>

#include <openssl/dsa.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>


/* globals */


/* protos */

void crypto_genkeypair(char **pub, char **priv);
int crypto_validate_keypair(char *pub, char *priv, char **correct);
void crypto_sign_info(char *message, char **sig);
int crypto_load_file(char *filename, int type, DSA **dsa);

void dots(int p, int n, void *dummy);

int b64_to_raw(char *b, u_char **r);
int raw_to_b64(char *r, int l, char **b);

/*******************************************/

void dots(int p, int n, void *dummy)
{
	char c = '*';

   if (!GBL_OPTIONS->verbose) return;
   
	if (p == 0) c = '.';
	if (p == 1) c = '+';
	if (p == 2) c = '*';
	if (p == 3) c = '\n';
	printf("%c", c);
	fflush(stdout);
}


void crypto_genkeypair(char **pub, char **priv)
{
	DSA *dsa;
	int counter, pub_DER, priv_DER;
   unsigned long h;
	BIO *bio_err;
   u_char *ptr;
   u_char pub_key[1024];
   u_char priv_key[1024];

   /*
    * feed the RND with entropy
    */
   
#ifdef HAVE_DEV_URANDOM
   RAND_load_file("/dev/urandom", 1024);
#elif defined(HAVE_DEV_RANDOM) 
   RAND_load_file("/dev/random", 1024);
#else
#warning randomness source not found !!
#endif
  
   if (RAND_status() != 1)
      ERROR_MSG("RAND has NOT been seeded with enough data");

   
   bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

   fprintf(stdout, "Generating prime numbers...\n\n");
   
   /*
    * generate prime numbers
    */
   
	dsa = DSA_generate_parameters(GBL_OPTIONS->bitlen, NULL, 0, &counter, &h, dots, NULL);
	if (dsa == NULL)
      ERROR_MSG("Can't generate DSA parameters");

   fprintf(stdout, "\n\nGenerating Key Pair... (%d bit)\n\n", BN_num_bits(dsa->p));
   
   /*
    * generate the key
    */
   
   if (DSA_generate_key(dsa) == -1)
      ERROR_MSG("Can't generate DSA keypair");
    
   if (GBL_OPTIONS->verbose)
      DSA_print(bio_err, dsa, 0);
   
   /*
    * convert the key to DER
    */
   
   ptr = pub_key;
   if ( (pub_DER = i2d_DSAPublicKey(dsa, &ptr)) == 0) 
      ERROR_MSG("Cant convert PublicKey to DER");

   ptr = priv_key;
   if ( (priv_DER = i2d_DSAPrivateKey(dsa, &ptr)) == 0) 
      ERROR_MSG("Cant convert PrivateKey to DER");
   
   /*
    * convert the public key
    */
  
   raw_to_b64(pub_key, pub_DER, pub);
   
   /*
    * convert the private key
    */
   
   raw_to_b64(priv_key, priv_DER, priv);
   
   /*
    * free the whole data
    */
   
   DSA_free(dsa);
   BIO_free(bio_err); 
}

int crypto_validate_keypair(char *pub, char *priv, char **correct)
{
	DSA *dsa, *dsa_pub;
	int len;
	BIO *bio_err;
   u_char *ptr, *ptrb;
   u_char buf[1024];
   char msg[] = "checkthisout";
   int siglen;
   u_char sig[1024];

   
   bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
   
   /*
    * convert from base64 to dsa key
    */
  
   len = b64_to_raw(priv, &ptr);
   
   ptrb = ptr;
   if ( (dsa = d2i_DSAPrivateKey(NULL, &ptrb, len)) == NULL)
      ERROR_MSG("Can't convert from DER");
   
   SAFE_FREE(ptr);
   
   /*
    * covert the base64 public key to another dsa struct
    */

   len = b64_to_raw(pub, &ptr);
   
   ptrb = ptr;
   if ( (dsa_pub = d2i_DSAPublicKey(NULL, &ptrb, len)) == NULL)
      ERROR_MSG("Can't convert from DER");

   SAFE_FREE(ptr);
   
   /*
    * check if they match
    */
  
   if (GBL_OPTIONS->verbose) {
      printf("\nFrom private key : \n\n"); 
      DSA_print(bio_err, dsa, 0);
      printf("\nFrom public key : \n\n"); 
      DSA_print(bio_err, dsa_pub, 0);
   }
  
   *correct = NULL;
   
   if ( DSA_sign(0, msg, strlen(msg), sig, &siglen, dsa) == -1 )
      EXIT_MSG("Can't sign with this key");

   if ( DSA_verify(0, msg, strlen(msg), sig, siglen, dsa_pub) != 1 ) {
   
      /*
       * the public key doesn't match the private one
       * calculate a new public from the private.
       * put in in *correct in base64 format
       */
           
      ptr = buf;
      if ( (len = i2d_DSAPublicKey(dsa, &ptr)) == 0) 
         ERROR_MSG("Cant convert PublicKey to DER");
  
      raw_to_b64(buf, len, correct);
   
      BIO_free(bio_err);
      DSA_free(dsa);
      DSA_free(dsa_pub);
      return -1;
   }
   
   BIO_free(bio_err);
   DSA_free(dsa);
   DSA_free(dsa_pub);
   return 0; 
}

void crypto_sign_info(char *message, char **sig)
{
   DSA *dsa;
   u_char sha[SHA_DIGEST_LENGTH];
   u_char signature[1024];
   int siglen;
   
   crypto_load_file(GBL_OPTIONS->file, LOAD_PRIV, &dsa);

   SHA1(message, strlen(message), sha);

   if (GBL_OPTIONS->verbose) {
      char *digest;
      raw_to_b64(sha, SHA_DIGEST_LENGTH, &digest);
      printf("SHA1 digest: %s", digest);
      SAFE_FREE(digest);
   }
   
   if ( DSA_sign(0, sha, SHA_DIGEST_LENGTH, signature, &siglen, dsa) == -1 )
      ERROR_MSG("Can't sign the info");
   
   raw_to_b64(signature, siglen, sig);
   
   if (GBL_OPTIONS->verbose)
      printf("SIG: %s", *sig);
}


int crypto_load_file(char *filename, int type, DSA **dsa)
{
   FILE *fd;
   char line[128];
   char *priv;
   u_char *ptr, *ptrb;
   int len;
        
   priv = calloc(1, sizeof(char));
   
   fd = fopen(filename, "r");
   ON_ERROR(fd, "Can't read %s", filename);
   
   while(fgets(line, 128, fd)) {
      if (line[0] == '-') continue;    /* skip header and trailer */
      
      priv = realloc(priv, strlen(priv) + strlen(line) + 1);
      ON_ERROR(priv, "can't allocate memory");
      
      strcat(priv, line);
   }
   
   fclose(fd);
  
   len = b64_to_raw(priv, &ptr);
   
   /*
    * create a dsa from private key
    */
   
   ptrb = ptr;
   
   switch (type) {
      case LOAD_PRIV:
         if ( (*dsa = d2i_DSAPrivateKey(NULL, &ptrb, len)) == NULL)
            ERROR_MSG("Can't convert from DER");
         break;
      case LOAD_PUB:
         if ( (*dsa = d2i_DSAPublicKey(NULL, &ptrb, len)) == NULL)
            ERROR_MSG("Can't convert from DER");
         break;
   }
   
   SAFE_FREE(ptr);
   SAFE_FREE(priv);

   return 1;
}

/* 
 * convert base64 to binary data
 */

int b64_to_raw(char *b, u_char **r)
{
   BIO *b64bio, *bio, *mbio;
   int len;
   int raw_len;

   /*
    * base64 encodes 6 bit per char, so if we have
    * the len of the base64 we can copute the raw
    * lan as folow:
    *    b64_len * 6 = number of bits
    *    n_bits / 8 = number of bytes
    *    
    * 6/8 == 3/4
    * 
    */
   
   raw_len = strlen(b) * 3 / 4 + 8;
   
   *r = calloc(1, raw_len);
   
   mbio = BIO_new_mem_buf(b, strlen(b));
   b64bio = BIO_new(BIO_f_base64());
   bio = BIO_push(b64bio, mbio);
   
   len = BIO_read(bio, *r, raw_len);
   
   BIO_free_all(bio);

   return len;
}

/*
 * convert binary data to base64
 */

int raw_to_b64(char *r, int l, char **b)
{
   BIO *b64bio, *bio, *mbio;
   u_char *p; 
   int h;
   
   mbio = BIO_new(BIO_s_mem());
   b64bio = BIO_new(BIO_f_base64());
   bio = BIO_push(b64bio, mbio);
   BIO_write(bio, r, l);
   BIO_flush(bio);
   
   h = BIO_get_mem_data(mbio, &p);
  
   *b = strndup(p, h);

   BIO_free_all(bio);
   
   return h;
}

/* EOF */

// vim:ts=3:expandtab

