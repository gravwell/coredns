# Gravwell CoreDNS plugin

The Gravwell CoreDNS plugin allows for directly integrating DNS auditing into Gravwell.  The plugin acts as an integrated ingester and ships DNS requests and responses directly to a Gravwell instance.

DNS Requests and responses can be encoded as text, JSON, or as a packed binary format.

## Building CoreDNS with the Gravwell plugin

```
go get github.com/coredns/coredns
pushd $GOPATH/src/github.com/coredns/coredns/
echo 'gravwell:github.com\/gravwell\/coredns/v1' >> plugin.cfg
go generate
CGO_ENABLED=0 go build -o /tmp/coredns
popd
```

The statically CoreDNS server with the Gravwell plugin will be located at /tmp/coredns

## Getting started with gravwell

Install Gravwell community edition https://dev.gravwell.io/docs/#!quickstart/community-edition.md

Grab a free Gravwell license https://www.gravwell.io/activate-community-edition

Configure your Corefile with an indexer target and your Ingest-Secret

### Example Corefile

```
.:53 {
  forward . 8.8.8.8:53 8.8.4.4:53 9.9.9.9:53
  errors stdout
  bind 10.0.0.1
  cache 240
  whoami
  gravwell {
   Ingest-Secret IngestSecretToken
   Cleartext-Target 192.168.1.1:4023
   Tag dns
   Encoding json
   Log-Level INFO
   #Cleartext-Target 192.168.1.2:4023 #second indexer
   #Ciphertext-Target 192.168.1.1:4024
   #Insecure-Novalidate-TLS true #disable TLS certificate validation
   #Ingest-Cache-Path /tmp/coredns_ingest.cache #enable the local ingest cache
   #Max-Cache-Size-MB 1024
  }
}
```
