# RSA PKCS#1 v1.5 (`sha256WithRSAEncryption`/`sha384WithRSAEncryption`) fixtures

These fixed fixtures were generated with OpenSSL for #645, the same pattern
as `tests/vectors/rsa_pss/README.md`:

```sh
printf 'Tardigrade RSA PKCS1v15 SHA-256/384 acceptance vector\n' >message.txt
openssl genrsa -traditional -3 2048 >private.pem
openssl rsa -in private.pem -RSAPublicKey_out -outform DER -out public-2048.der
openssl dgst -sha256 -sign private.pem -out signature-sha256-2048.bin message.txt
openssl dgst -sha384 -sign private.pem -out signature-sha384-2048.bin message.txt
```

`public-2048.der` contains an `RSAPublicKey` value; the two signature files
are real EMSA-PKCS1-v1_5 signatures over `message.txt` with a 2048-bit
modulus, for SHA-256 and SHA-384 respectively. The private key is
intentionally not checked in.
