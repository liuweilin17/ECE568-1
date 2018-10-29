#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "sslutinity.h"


#define HOST "localhost"
#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"


/* Configuration Define and Setting Variable*/
// #define KEY_FILE_PATH "alice.pem"

#define KEY_FILE_PATH "./testCert/testAliceCert.pem"

#define CLIENT_PASSWORD "password"
#define SERVER_CERT_EMAIL "ece568bob@ecf.utoronto.ca"
#define SERVER_CN "Bob's Server"
#define BUFSIZZ 256


static int require_server_auth=1;


// Declaration of function
int tcp_connect(char* host, int port);
void check_cert(SSL* ssl, char* host);
static int request_and_response(SSL *ssl, char *req, char *buf);


/*---------------------------------TCP Connection-------------------------------*/
int tcp_connect(char* host, int port){
  int sock;
  struct hostent *host_entry;
  struct sockaddr_in addr;

  /*get ip address of the host*/
  host_entry = gethostbyname(host);  
  if (!host_entry){
    fprintf(stderr,"Couldn't resolve host");
    exit(0);
  }


  /*  
    Filling in addr variable which is of type sockaddr_in. struct sockaddr_in is the structure used 
    with IPv4 addresses (e.g. "192.0.2.10"). It holds an address family (AF_INET), 
    a port in sin_port, and an IPv4 address in sin_addr.
  */
  memset(&addr,0,sizeof(addr));
  addr.sin_addr=*(struct in_addr *) host_entry->h_addr_list[0];
  addr.sin_family=AF_INET;

  /* The htons() function converts the unsigned short integer hostshort 
  from host byte order to network byte order. */
  addr.sin_port=htons(port); 


  printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr),port);
  
  /*open socket*/
  if((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)  //creates socket
    perror("Error: Couldn't create socket");
  if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0)  //connects
    perror("Error: Couldn't connect to socket");

  return sock;

}



/*---------------------------------Certicafation Check-------------------------------*/
void check_cert(SSL* ssl, char* host) {
    X509 *peer;
    char peer_CN[256];

    /*Check the cert chain. The chain length
      is automatically checked by OpenSSL when
      we set the verify depth in the ctx */

    /*Check the common name*/
    peer=SSL_get_peer_certificate(ssl);
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_commonName, peer_CN, 256);

    if(SSL_get_verify_result(ssl)!=X509_V_OK)
      berr_exit("Certificate doesn't verify");
      
    if ((peer == NULL) || (SSL_get_verify_result(ssl) != X509_V_OK)){
      printf(FMT_NO_VERIFY);
      return -1;
    }

    // Set peer email and issuer
    char peer_email[256];
    char peer_certi_issuer[256];

    // Get peer's email and issuer
    X509_NAME_get_text_by_NID (X509_get_subject_name(peer), NID_pkcs9_emailAddress, peer_email, 256);  
    X509_NAME_get_text_by_NID (X509_get_issuer_name(peer), NID_commonName, peer_certi_issuer, 256);
    
    //printf(FMT_OUTPUT,peer_CN, peer_email);
    // check Email and Issuer

    if(strcasecmp(peer_email, SERVER_CERT_EMAIL) && strcasecmp(peer_CN, SERVER_CN)){
      printf(FMT_CN_MISMATCH);
      printf(FMT_EMAIL_MISMATCH);
      exit(0);
    }

    if(strcasecmp(peer_email, SERVER_CERT_EMAIL))
      err_exit(FMT_EMAIL_MISMATCH);

    if(strcasecmp(peer_CN, SERVER_CN))
      err_exit(FMT_CN_MISMATCH);
    

    //printf("%s\n",peer_certi_issuer);

    printf(FMT_SERVER_INFO, peer_CN, peer_email, peer_certi_issuer);

    return;
  }


/*--------------------Request and Response (Write and read)--------------*/
static int request_and_response(SSL *ssl, char *req, char *buf){

    //char buf[BUFSIZZ];
    int r;
    int len;

    int request_len;

    request_len = strlen(req);

    r = SSL_write(ssl,req,request_len);


    switch(SSL_get_error(ssl,r)){      
      case SSL_ERROR_NONE:
        if(request_len!=r)
          err_exit("Incomplete Write");
        break;
      default:
          berr_exit("SSL Write Error");
    }



    /* Now read the server's response, assuming
       that it's terminated by a close */

    while(1){
      r=SSL_read(ssl,buf,BUFSIZZ);
      //printf("%d \n", r);


      switch(SSL_get_error(ssl,r)){
        case SSL_ERROR_NONE:
          len=r;
	  //printf("SSL_ERROR_NONE");
          break;
        case SSL_ERROR_ZERO_RETURN:
          goto shutdown;
        case SSL_ERROR_SYSCALL:
          printf("SSL_ERROR_SYSCAL");
          fprintf(stderr,
            "SSL Error: Premature close\n");
	  exit(0);
        default:
          berr_exit("SSL read problem");
      }
      buf[len]='\0';
	//fprintf(FMT_OUTPUT, req, buf);
//fprintf(stderr,"test\n");
      //fwrite(buf,1,len,stdout);
      
    }
    
  shutdown:
    r=SSL_shutdown(ssl);
    switch(r){
      case 1:
        break; /* Success */
      case 0:
      case -1:
      default:
        berr_exit("Shutdown failed");
    }
    
  done:
    SSL_free(ssl);
    return(0);
  }
    




int main(int argc, char **argv)
{
  int len;
  int sock, port=PORT;
  char *host=HOST;
  //struct sockaddr_in addr;
  //struct hostent *host_entry;
  char buf[256];
  char *secret = "What's the question?";
  
  /*Parse command line arguments*/
  
  switch(argc){
    case 1:
      break;
    case 3:
      host = argv[1];
      port=atoi(argv[2]);
      if (port<1||port>65535){
	fprintf(stderr,"invalid port number");
	exit(0);
      }
      break;
    default:
      printf("Usage: %s server port\n", argv[0]);
      exit(0);
  }
 

  // SSL HANDSHAKE
  // build a TCP connection
  sock = tcp_connect(host, port);
  // Initialize a SSL context w/ alice key and password
  SSL_CTX *ctx = initialize_ctx(KEY_FILE_PATH, CLIENT_PASSWORD);
  // Use SSLv3 or TSLv1. No SSLv2
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
  // Use SHA1 only for cipher
  SSL_CTX_set_cipher_list(ctx, "SHA1");
  // test case
  //SSL_CTX_set_cipher_list(ctx, "AES256");

  // build a new SSL connection and attach the BIO object for stdin or stdout
  SSL *ssl;
  BIO *sbio;

  ssl = SSL_new(ctx);
  sbio = BIO_new_socket(sock,BIO_NOCLOSE);
  SSL_set_bio(ssl,sbio,sbio);

  //printf("%d \n", SSL_connect(ssl) );
  if (SSL_connect(ssl) <= 0) {
    //printf("%d \n", SSL_connect(ssl) );
    // printf(FMT_CONNECT_ERR);
    berr_exit(FMT_CONNECT_ERR);
    //err_exit(FMT_CONNECT_ERR);
  }

  if (require_server_auth) {
    check_cert(ssl, host);

    request_and_response(ssl, secret, &buf);

    
    /* this is how you output something for the marker to pick up */
    printf(FMT_OUTPUT, secret, buf);
    
  }

  destroy_ctx(ctx);
  close(sock);
  return 1;
}
