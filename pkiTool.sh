#!/bin/bash

mkdir PKI
mkdir ./PKI/private
mkdir ./PKI/certs
mkdir ./PKI/crl
mkdir ./PKI/newcerts
touch ./PKI/index.txt
echo 01 > ./PKI/serial

# Get the hostfile from the command line argument
exec < $1

# Location to config file
config="./openssl.cnf"

# Generate private key for CA
openssl genrsa -out ./PKI/private/cakey.pem 2048

# Generate certificate (public key) for CA
openssl req -batch -new -x509 -extensions v3_ca -key ./PKI/private/cakey.pem -out ./PKI/cacert.pem -days 365

while read line
do
	touch ./PKI/index.txt
	echo 01 > ./PKI/serial

	# Generate private key for host with id = $line
	openssl genrsa -out ./PKI/host_"$line"_key.pem 2048

	# Generate certificate (public key) for host with id = $line
	openssl req -batch -new -extensions v3_ca -key ./PKI/host_"$line"_key.pem -out ./PKI/host_"$line"_cert_req.pem -days 365

	# Sign the certificate by the CA
	openssl ca -batch -out ./PKI/host_"$line"_cert.pem -keyfile ./PKI/private/cakey.pem -cert ./PKI/cacert.pem -config $config -infiles ./PKI/host_"$line"_cert_req.pem

	rm -rf ./PKI/index*
	rm -rf ./PKI/serial*
done

