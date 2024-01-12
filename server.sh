#!/bin/bash

openssl s_server -key key.pem -cert cert.pem -accept 8443 -tls1
