# Test certificates

A throwaway certificate authority and a server certificate signed by it, for the DoT and DoH tests.
They are **test-only**: the private key is public, so nothing should ever trust `ca.pem` outside
these tests.

- `ca.pem`: the test CA (the CA's private key was discarded after signing).
- `server.pem`, `server.key`: a certificate for `dns.goethite.test` and `127.0.0.1`, and its
  PKCS#8 key.

Both are valid for 100 years. They were generated with OpenSSL 3:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout ca.key -out ca.pem -days 36500 -subj "/CN=goethite test CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout server.key -out server.csr -subj "/CN=dns.goethite.test"
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem \
  -days 36500 -extfile server.ext   # SAN DNS:dns.goethite.test, IP:127.0.0.1; EKU serverAuth
openssl pkcs8 -topk8 -nocrypt -in server.key -out server.key
```
