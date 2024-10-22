These certificates for testing are generated with https://github.com/cloudflare/cfssl

Run the following commands to generate the certificates:


# Generate the CA key and cert

```bash
cfssl gencert -initca ca-csr.json | cfssljson -bare ca
```

# Generate the Server key and cert

```bash
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=server server-csr.json| cfssljson -bare server
```

# Generate the Client key and cert
```bash
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=client client-csr.json | cfssljson -bare client
```

# Generate second Client key and cert
```bash
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=client second-client-csr.json | cfssljson -bare second-client
```
