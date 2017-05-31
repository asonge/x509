#include "stdio.h"
#include "string.h"
#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/x509.h"
#include "openssl/x509_vfy.h"
// #include "openssl/crypto.h"

#define OK 1

X509 * read_pem_file(const char *filename);
int read_pem_file_multi(const char *filename, STACK_OF(X509) **certs);
void print_help(const char *cmd);
void print_error(X509_STORE_CTX *ctx);
int sign_file(const char *pk_file, const char *file);
int verify_cert(const char *ca_file, const char *chain_file, X509 *cert);
int verify_cert_and_signature(const char *ca_file, const char *cert_file, const char *chain_file, const char *sign_file, const char *file);

int main(int argc, char *argv[]) {
  if(argc < 2) {
    print_help(argv[0]);
    return 1;
  }
  // If the following line is missing, nothing works and you will not know why.
  OpenSSL_add_all_algorithms();
  if(strcmp(argv[1],"sign")==0 && argc==4) {
    return sign_file(argv[2], argv[3]);
  } else if(strcmp(argv[1],"verify")==0 && argc==6) {
    return verify_cert_and_signature(argv[2], argv[3], NULL, argv[4], argv[5])==OK ? 0 : 1;
  } else if(strcmp(argv[1],"verify")==0 && argc==7) {
    return verify_cert_and_signature(argv[2], argv[3], argv[4], argv[5], argv[6])==OK ? 0 : 1;
  } else {
    print_help(argv[0]);
    return 1;
  }
}

const int BUF_SIZE = 4096;

int sign_file(const char *pk_file, const char *sign_file) {
  unsigned char buf[BUF_SIZE];
  size_t bytes_read;
  const EVP_MD *md = EVP_sha256();

  EVP_MD_CTX *ctx = EVP_MD_CTX_create();
  FILE *fp = fopen(pk_file, "r");
  if(!fp) {
    printf("Could not read file %s\n", pk_file);
    return !OK;
  }
  EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
  fclose(fp);
  
  unsigned int key_size = EVP_PKEY_size(pkey);
  unsigned char signature[key_size];
  unsigned int sig_size;

  fp = fopen(sign_file, "rb");
  if(!fp) {
    printf("Could not read file %s\n", sign_file);
    return !OK;
  }
  EVP_SignInit(ctx, md);
  while((bytes_read = fread(buf, 1, BUF_SIZE, fp)) > 0) {
    EVP_SignUpdate(ctx, buf, bytes_read);
  }
  fclose(fp);
  EVP_SignFinal(ctx, signature, &sig_size, pkey);

  BIO *bio, *b64;
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new_fp(stdout, BIO_NOCLOSE);
  bio = BIO_push(b64, bio);

  BIO_write(bio, signature, sig_size);
  BIO_flush(bio);
  BIO_free_all(bio);
  
  return OK;
}

int verify_signature(X509 *cert, const char *sign_file, const char *file);

int verify_cert_and_signature(const char *ca_file, const char *cert_file, const char *chain_file, const char *sign_file, const char *file) {
  // The certificate we want to validate
  X509 *cert = NULL;
  cert = read_pem_file(cert_file);
  if(cert==NULL) {
    printf("Not a valid cert!\n");
    return !OK;
  }

  return verify_cert(ca_file, chain_file, cert)==OK && verify_signature(cert, sign_file, file)==OK;
}

int verify_signature(X509 *cert, const char *sign_file, const char *file) {
  int ret;
  FILE *fp;
  unsigned char buf[BUF_SIZE];
  size_t bytes_read;
  const EVP_MD *md = EVP_sha256();
  EVP_MD_CTX *ctx = EVP_MD_CTX_create();

  // Let's read in the signature data
  EVP_PKEY *pkey = X509_get_pubkey(cert);
  BIO *bio = BIO_new_file(sign_file, "rb");
  BIO *b64 = BIO_new(BIO_f_base64());
  bio = BIO_push(b64, bio);
  
  unsigned int key_size = EVP_PKEY_size(pkey);
  unsigned char signature[key_size];
  unsigned int sig_size=0, read_bytes;

  while((read_bytes=BIO_read(bio, &signature[sig_size], BUF_SIZE)) > 0) {
    printf("Read %d of possible %d\n", read_bytes, key_size);
    sig_size += read_bytes;
  }
  
  printf("Read in %d of signature file\n", sig_size);
  BIO_free_all(bio);
  // Done reading in signature data.

  // Let's read in the file we want to sign
  fp = fopen(file, "rb");
  if(!fp) {
    printf("Could not read file %s\n", sign_file);
    return !OK;
  }
  EVP_VerifyInit(ctx, md);
  while((bytes_read = fread(buf, 1, BUF_SIZE, fp)) > 0) {
    EVP_VerifyUpdate(ctx, buf, bytes_read);
  }
  ret = EVP_VerifyFinal(ctx, signature, sig_size, pkey);
  fclose(fp);
  EVP_MD_CTX_destroy(ctx);
  return ret;
}

int verify_cert(const char *ca_file, const char *chain_file, X509 *cert) {
  int ret;
  // The trusted store
  X509_STORE *store;
  // The lookup method for the trusted store
  X509_LOOKUP *lookup;
  // The context for verifying a certificate
  X509_STORE_CTX *ctx;
  // A stack of intermediate certificates to validate
  STACK_OF(X509) *chain = NULL;

  store = X509_STORE_new();
  lookup = X509_STORE_add_lookup(store,X509_LOOKUP_file());
  ret = X509_LOOKUP_load_file(lookup, ca_file, X509_FILETYPE_PEM);
  if(ret!=1) {
    printf("Could not read file %s for reason: %d\n", ca_file, ret);
    return 1;
  }

  ctx = X509_STORE_CTX_new();
  ret = X509_STORE_CTX_init(ctx, store, cert, chain);
  if(ret!=1) {
    printf("Result of store ctx init: %d\n", ret);
    return 1;
  }
  ret = X509_verify_cert(ctx);
  if(ret<1 || X509_STORE_CTX_get_error(ctx) != X509_V_OK) {
    printf("Result of store ctx validate: %d\n", ret);
    print_error(ctx);
    
    int j;
    STACK_OF(X509) *chain = X509_STORE_CTX_get1_chain(ctx);
    int num_untrusted = ctx->last_untrusted;
    for (j = 0; j < sk_X509_num(chain); j++) {
      X509 *cert = sk_X509_value(chain, j);
      printf("depth=%d: ", j);
      X509_NAME_print_ex_fp(stdout,
                            X509_get_subject_name(cert),
                            0, 0);
      if (j < num_untrusted)
        printf(" (untrusted)");
      printf("\n");
    }
    sk_X509_pop_free(chain, X509_free);

    return !OK;
  }
  
  return OK;
}

void print_help(const char *cmd) {
  printf("Usage:\n");
  printf("\t%s sign keyfile filetosign\n", cmd);
  // printf("\t%s verify selfsigned_cert signedfile\n", cmd);
  printf("\t%s verify cafile certfile signaturefile filetosign\n", cmd);
  printf("\t%s verify cafile certfile chainfile signaturefile filetosign\n", cmd);
}

void print_error(X509_STORE_CTX *ctx) {
  int cert_error = X509_STORE_CTX_get_error(ctx);
  const char *error_str = X509_verify_cert_error_string(cert_error);

  X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
  X509_NAME *cert_name = X509_get_subject_name(cert);

  printf("Error (%d): %s\n", cert_error, error_str);
  printf("While evaluating certificate:\n  ");
  X509_NAME_print_ex_fp(stdout, cert_name, 2, 0);
  printf("\n");
}

X509 * read_pem_file(const char *filename) {
  FILE *fp = fopen(filename, "r");
  if(fp==NULL) {
    printf("Cound not read file %s\n", filename);
    return NULL;
  }
  return PEM_read_X509(fp, NULL, NULL, NULL);
}

int read_pem_file_multi(const char *filename, STACK_OF(X509) **certs) {
  int i;
  int ret = 0;
  
  STACK_OF(X509_INFO) *infos = NULL;
  X509_INFO *info = NULL;
  
  BIO *input = BIO_new_file(filename, "r");
  if(input==NULL) {
    printf("Could not read file %s\n", filename);
    return -1;
  }
  infos = PEM_X509_INFO_read_bio(input, NULL, NULL, NULL);
  
  BIO_free(input);

  for(i=0; i < sk_X509_INFO_num(infos); i++) {
    info = sk_X509_INFO_value(infos, i);
    if(info->x509==NULL) continue;
    if(!sk_X509_push(*certs, info->x509)) {
      ret = -1;
      goto cleanup;
    }
    ret++;
  }
cleanup:
  sk_X509_INFO_pop_free(infos, X509_INFO_free);
  return ret;
}
