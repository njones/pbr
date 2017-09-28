#! /bin/bash

# How to make the example openssl PEM blocks for testing
# Each section should have a way to create an view the different cert types

### RSA ###

# RSA - Create a Private Key
openssl genrsa -out localhost.rsa.key 2048

# RSA - Create a CSR
openssl req -out localhost.rsa.csr -key localhost.rsa.key -new

# RSA - Create a self-signed Certificate
openssl x509 -req -days 365 -in localhost.rsa.csr -signkey localhost.rsa.key -out localhost.rsa.crt

# RSA - Display a Private Key
openssl rsa -in localhost.rsa.key -check

# RSA - Display a CSR
openssl req -in localhost.rsa.csr -text -noout

# RSA - Display a Certificate
openssl x509 -in localhost.rsa.crt -text -noout