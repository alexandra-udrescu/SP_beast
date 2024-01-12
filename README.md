# Install notes
Pick a path for an outdated local installation of `OpenSSL`. In our case, we used [OpenSSL v1.0.0t](https://www.openssl.org/source/old/1.0.0/) and `/home/bob/SP_infrastructure/` as the root directory for the installation.

```
export LDFLAGS="-L/home/bob/SP_infrastructure/local/lib -lcrypto"
export CFLAGS="-Wall -g -I/home/bob/SP_infrastructure/local/include"

./config --prefix=/home/bob/SP_infrastructure/local --openssldir=/home/bob/SP_infrastructure/local/openssl
make
make test
make install
```

From there on, commands will be ran from the local installation, i.e.:
```
alias oldssl='/home/bob/SP_infrastructure/local/bin/openssl'

oldssl s_server -key key.pem -cert cert.pem -accept 44330 -tls1
oldssl s_client -connect localhost:44330 -cipher AES128-SHA
```

# Execution notes

The provided scrips assume the command for the recommended version of OpenSSL is the classic one, it is advised to manually change it to the chosen alias.

To create the server, a private key and a self-signed certificate must be generated:
```
./certificate.sh
```

In one terminal run the server:
```
./server.sh
```

In another terminal run:
```
sudo python3 poc_client.py
```
This is the proof-of-concept that shows that by sending conveniently padded secrets, they can be intercepted by a man-in-the-middle and then decrypted to reveal sensitive data.

To visualize the packets sent that are tls 1.0:
```
sudo tcpdump -i lo -s 0 -A -nn -X 'tcp port 8443 and (ether[0x68] = 0x03) and (ether[0x69] = 0x01)'
```
