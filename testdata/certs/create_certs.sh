#!/usr/bin/env bash
# Credits: https://github.com/jcbsmpsn/golang-https-example

# Create CA key + certificate
openssl req \
    -newkey rsa:2048 \
    -nodes \
    -days 3650 \
    -x509 \
    -keyout ca.key \
    -out ca.crt \
    -subj "/CN=*"

# Create server certificate request and key
openssl req \
    -newkey rsa:2048 \
    -nodes \
    -keyout server.key \
    -out server.csr \
    -subj "/C=GB/ST=London/L=London/O=libvault consultants/OU=IT Department/CN=*"

# Sign the server certificate request with the CA key
# adding SAN IP
openssl x509 \
    -req \
    -days 365 \
    -sha256 \
    -in server.csr \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out server.crt \
    -extfile <(echo subjectAltName = IP:127.0.0.1)
