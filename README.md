# Gravwell CoreDNS plugin

The Gravwell CoreDNS plugin allows for directly integrating DNS auditing into Gravwell.  The plugin acts as an integrated ingester and ships DNS requests and responses directly to a Gravwell instance.

DNS Requests and responses can be encoded as text, JSON, or as a packed binary format.

## CoreDNS Kit in Gravwell

Gravwell provides a CoreDNS Kit to work with data ingested by CoreDNS out of the box and provides a number of prebuilt queries, dashboards, and investigation tools. 

![Gravwell CoreDNS Kit](https://raw.githubusercontent.com/gravwell/coredns/main/coredns_kit.png)


## Building CoreDNS with the Gravwell plugin

```
git clone https://github.com/coredns/coredns.git
pushd coredns
sed -i 's/metadata:metadata/metadata:metadata\ngravwell:github.com\/gravwell\/coredns/g' plugin.cfg
go generate
go get github.com/gravwell/coredns
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /tmp/coredns
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
