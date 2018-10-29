#include "sslutinity.h"
#include <openssl/err.h>

BIO *bio_err=0;
static char *pass;
static int password_cb(char *buf,int num, int rwflag,void *userdata);
static void sigpipe_handle(int x);


int err_exit(char* error)
{
    fprintf(stderr,"%s\n",error);
    exit(0);
}


// SSL errors
int berr_exit(char* error)
{
    BIO_printf(bio_err,"%s\n",error);
    ERR_print_errors(bio_err);
    exit(1);
}


static void sigpipe_handle(int x){}


SSL_CTX *initialize_ctx(char* keyfile, char* password)
{
    SSL_METHOD *meth;
    SSL_CTX *ctx;

    if(!bio_err){
        /* Global system initialization*/
        SSL_library_init();
        SSL_load_error_strings();

        /* An error write context */
        bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
    }

    /* Set up a SIGPIPE handler */
    signal(SIGPIPE,sigpipe_handle);

    /* Create our context*/
    meth=SSLv23_method();
    // test case - not support SSLv3
    // meth=SSLv2_method();
    ctx=SSL_CTX_new(meth);

    /* Load our keys and certificates*/
    if(!(SSL_CTX_use_certificate_chain_file(ctx, keyfile)))
        berr_exit("Can’t read certificate file\n");

    pass=password;
    SSL_CTX_set_default_passwd_cb(ctx, password_cb);
    if(!(SSL_CTX_use_PrivateKey_file(ctx, keyfile,SSL_FILETYPE_PEM)))
        berr_exit("Can’t read key file\n");

    /* Load the CAs we trust*/
    if(!(SSL_CTX_load_verify_locations(ctx, CA_LIST,0)))
        berr_exit("Ca’t read CA list\n");
    #if (OPENSSL_VERSION_NUMBER < 0x0090600fL)
    SSL_CTX_set_verify_depth(ctx,1);
    #endif

    return ctx;
}


/*PasswordCode: not thread safe*/
static int password_cb(char *buf, int num, int rwflag, void *userdata)
{
    if(num<strlen(pass)+1) {
      return(0);
    }

    strcpy(buf,pass);
    return(strlen(pass));
}



void destroy_ctx(SSL_CTX* ctx)
{
    SSL_CTX_free(ctx);
}
