#!/bin/bash

openssl genpkey -algorithm RSA -out key.pem
openssl req -x509 -new -key key.pem -out cert.pem
