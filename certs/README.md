# Extra CA certificates

Leave this directory empty unless your network inspects TLS: a corporate proxy that re-signs HTTPS traffic with its own root certificate. Behind such a proxy the build fails with errors like:

```
SSL: CERTIFICATE_VERIFY_FAILED ... self-signed certificate in certificate chain   (pip)
SELF_SIGNED_CERT_IN_CHAIN / UNABLE_TO_GET_ISSUER_CERT_LOCALLY                      (npm)
```

Put your organisation's root (and any intermediate) certificate here as a **PEM** file ending in `.crt` or `.pem`. A file may hold several certificates. Every image trusts them at build time and at run time; with no files here, nothing changes.

`./install.sh --ca-file /path/to/root-ca.pem` copies the file here for you. To export the certificate, check that it works and rebuild an existing install, see "Corporate networks" in [ADMIN_GUIDE.md](../ADMIN_GUIDE.md#corporate-networks-tls-inspection-and-private-mirrors).

Only certificates go here, never private keys. Everything in this directory except this README is ignored by git.
