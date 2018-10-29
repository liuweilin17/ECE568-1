#ifndef sslutinity_h
#define sslutinity_h


#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>



#define HOST	"localhost"
//#define CA_LIST "568ca.pem"
// Test case
#define CA_LIST "./testCert/testCert.pem"

#define PASSWORD "password"
#define BUFSIZE 256
#define PORT	8765



extern BIO *bio_err;
int berr_exit(char *string);
int err_exit(char *string);


SSL_CTX *initialize_ctx(char *keyfile, char *password);
void destroy_ctx(SSL_CTX *ctx);





#endif
