#/bin/bash

# Purge all existing files
rm serial*
echo 10001 > serial
rm certindex.txt*
touch certindex.txt
rm certs/*
rm private/*
rm requests/*

# Generate Certificate Authority
openssl req -new -x509  -extensions v3_ca -keyout private/568ca.pem -out 568ca.pem -days 365 -config openssl.cnf 

openssl x509 -noout -text -in 568ca.pem 


#Generate Alice's private key and CSR (Certificate Signing Request)
openssl req -new -nodes -out alice-request.pem -keyout private/alice.pem -days 365 -config openssl.cnf 
openssl req -text -in alice-request.csr 

# Sign Alice's key
openssl ca -out certs/alice.pem -days 365 -config openssl.cnf -infiles alice-request.csr


#Generate Bob's private key and CSR (Certificate Signing Request)
openssl req -new -nodes -out bob-request.csr -keyout private/bob.pem -days 365 -config openssl.cnf
# Sign Bob's key
openssl ca -out certs/bob.pem -days 365 -config openssl.cnf -infiles bob-request.csr



# one liner
#openssl req -new -nodes -x509 -keyout key.pem -out cert.crt -days 356 -subj “/C=CA/ST=Ontario/L=Toronto/O=University of Toronto/CN=Bob's Server”