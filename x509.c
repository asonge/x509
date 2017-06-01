#include "stdio.h"
#include "string.h"
#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/x509.h"
#include "openssl/x509_vfy.h"

const int OK = 1;
const int BUF_SIZE = 4096;

int sign(const char *pk_file, const char *file);

int verify(const char *ca_file, const char *cert_file, const char *chain_file, const char *sign_file, const char *file);
int verify_cert(const char *ca_file, const char *chain_file, X509 *cert);
int verify_signature(X509 *cert, const char *sign_file, const char *file);

void print_help(const char *cmd);
void print_error(X509_STORE_CTX *ctx);

X509 * read_pem_file(const char *filename);
BIO * bio_base64_file(const char *filename);
int read_pem_file_multi(const char *filename, STACK_OF(X509) **certs);
BIO * fopen_bio(const char *filename);
EVP_MD_CTX *md_sign_or_verify_file(const char *filename, EVP_PKEY *pkey, const EVP_MD *md);

int main(int argc, char *argv[]) {
  if(argc < 2) {
    print_help(argv[0]);
    return 1;
  }
  // If the following line is missing, nothing works and you will not know why.
  OpenSSL_add_all_algorithms();
  if(strcmp(argv[1],"sign")==0 && argc==4) {
    return sign(argv[2], argv[3])==OK ? 0 : 1;
  } else if(strcmp(argv[1],"verify")==0 && argc==6) {
    return verify(argv[2], argv[3], NULL, argv[4], argv[5])==OK ? 0 : 1;
  } else if(strcmp(argv[1],"verify")==0 && argc==7) {
    return verify(argv[2], argv[3], argv[4], argv[5], argv[6])==OK ? 0 : 1;
  } else {
    print_help(argv[0]);
    return 1;
  }
}

int sign(const char *pk_file, const char *sign_file) {
  int ret;
  EVP_MD_CTX *ctx = NULL;
  
  BIO *bio = fopen_bio(pk_file);
  // TODO: implement pw prompt:
  // https://www.openssl.org/docs/man1.0.2/crypto/PEM_read_bio_PrivateKey.html
  EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  BIO_free_all(bio);
  if(pkey==NULL) {
    return !OK;
  }
  
  void *signature = malloc(EVP_PKEY_size(pkey));
  unsigned int sig_size;

  ctx = md_sign_or_verify_file(sign_file, pkey, EVP_sha256());
  ret = EVP_SignFinal(ctx, signature, &sig_size, pkey);
  if(ret==1) {
    bio = bio_base64_file("-");
    BIO_write(bio, signature, sig_size);
    BIO_flush(bio);
    BIO_free_all(bio);
  }
  free(signature);
  EVP_MD_CTX_destroy(ctx);
  return ret==1 ? OK : !OK;
}

int verify(const char *ca_file, const char *cert_file, const char *chain_file, const char *sign_file, const char *file) {
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
  BIO *bio = NULL;
  EVP_MD_CTX *ctx = NULL;

  // Let's read in the signature data
  EVP_PKEY *pkey = X509_get_pubkey(cert);

  bio = bio_base64_file(sign_file);
  unsigned char *signature = malloc(EVP_PKEY_size(pkey));
  unsigned int sig_size=0, read_bytes;
  while((read_bytes=BIO_read(bio, &signature[sig_size], BUF_SIZE)) > 0) {
    sig_size += read_bytes;
  }
  if(sig_size==0) {
    printf("Could not read data from signature file %s, maybe not valid base64?\n", sign_file);
    ret = 0;
    goto cleanup;
  }
  // TODO exit/warn if we've read 0 bytes, possibly not in base64 then.
  
  // Done reading in signature data.
  ctx = md_sign_or_verify_file(file, pkey, EVP_sha256());
  ret = EVP_VerifyFinal(ctx, signature, sig_size, pkey);
  
cleanup:
  if(bio!=NULL) BIO_free_all(bio);
  if(ctx!=NULL) EVP_MD_CTX_destroy(ctx);
  return ret==1 ? OK : !OK;
}

int verify_cert(const char *ca_file, const char *chain_file, X509 *cert) {
  int ret;
  X509_STORE *store;             // The trusted store
  X509_LOOKUP *lookup;           // The lookup method for the trusted store
  X509_STORE_CTX *ctx;           // The context for verifying a certificate
  STACK_OF(X509) *chain = NULL;  // A stack of intermediate certificates to validate

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

BIO * fopen_bio(const char *filename) {
  if(strcmp(filename,"-")==0) {
    return BIO_new_fp(stdout, BIO_NOCLOSE);
  } else {
    return BIO_new_file(filename, "rb");
  }
}
BIO * bio_base64_file(const char *filename) {
  BIO *bio, *b64;
  bio = fopen_bio(filename);
  b64 = BIO_new(BIO_f_base64());
  return BIO_push(b64, bio);
}
// EVP_VerifyInit and EVP_SignInit, EVP_VerifyUpdate and EVP_SignUpdate are all actually
// EVP_DigestInit and EVP_DigestUpdate, so we can collect some repeated code here.
EVP_MD_CTX *md_sign_or_verify_file(const char *filename, EVP_PKEY *pkey, const EVP_MD *md) {
  BIO *bio = fopen_bio(filename);
  int bytes_read = 0;
  unsigned char buf[BUF_SIZE];

  EVP_MD_CTX *ctx = EVP_MD_CTX_create();
  EVP_DigestInit(ctx, md);
  while((bytes_read=BIO_read(bio, buf, BUF_SIZE))>0) {
    EVP_DigestUpdate(ctx, buf, bytes_read);
  }
  BIO_free_all(bio);
  return ctx;
}


X509 * read_pem_file(const char *filename) {
  BIO *bio = fopen_bio(filename);
  X509 *x = PEM_read_bio_X509(bio, NULL, NULL, NULL);
  BIO_free_all(bio);
  if(!x) {
    printf("Could not read certificate from %s\n", filename);
  }
  return x;
}

int read_pem_file_multi(const char *filename, STACK_OF(X509) **certs) {
  int i;
  int ret = 0;
  
  STACK_OF(X509_INFO) *infos = NULL;
  X509_INFO *info = NULL;
  
  BIO *bio = fopen_bio(filename);
  infos = PEM_X509_INFO_read_bio(bio, NULL, NULL, NULL);
  BIO_free_all(bio);

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
