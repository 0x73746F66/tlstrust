# tlstrust

Utilities that assist with trust relationship checking of X.509 Certificates for various end-user devices with disparate root trust stores.

## [Documentation](https://gitlab.com/trivialsec/tlstrust/-/blob/main/docs/0.index.md)

In your app you can:

```py
import os
from pathlib import Path
from OpenSSL.crypto import FILETYPE_ASN1
from tlstrust import TrustStore
from tlstrust.context import PLATFORM_JAVA

der = Path(os.path.join(os.path.dirname(__file__), "cert.der")).read_bytes()
trust_store = TrustStore(FILETYPE_ASN1, der)
assert trust_store.check_trust()
assert trust_store.check_trust(PLATFORM_JAVA)
```

## [Change Log](https://gitlab.com/trivialsec/tlstrust/-/blob/main/docs/z.change-log.md)

# Platform Specific evaluations of trust

While `tlstrust` is a tool for evaluations of trust where certificates are presented for HTTPS/TLS use, i.e. generally considered the certificate will be used for web browsers.

There is an explosion of microservice architectures where one endpoint acts in usual place of a web browser using code, where these programming languages **never** implement or offer the means to verify trust unless the developer, each and every time an they code any TLS usage, explicitly interrogates the full certificate chain and evaluates trust (which is inevitably not performed).

With the rise of Zero-Trust architectures, where trust must be given only after verification assurances are gained, the TLS Certificate chain validation on each endpoint must critically apply suitable evaluation of the entire Certificate chain. Lacking these evaluations a Zero-Trust architecture inherently trusts the issued certificates and never verifies if they are trust-'worthy'. This is the sad state in many Zero-Trust architectures, a consistent finding in penetration testing reports completed by competent testers who routinely forge certificates to by-pass Certificate-based Authentication mechanisms common in Zero-Trust architectures.

For this reason `tlstrust` can be used to perform platform specific evaluations for common platforms where Zero-Trust architectures operate in addition to the typical Web Browser checks.

## Apple (iOS, iPadOS, macOS, tvOS, and watchOS)

[Coming into effect December 1, 2021](https://www.apple.com/certificateauthority/ca_program.html) Apple will use Common CA Certificate Database (CCADB) and enforced April 1, 2022.

For this reason `tlstrust` will derive it's result from evaluations of trust for Apple evaluations using the Common CA Certificate Database (CCADB).

## Windows

[Microsoft Trusted Root Program](https://docs.microsoft.com/en-us/security/trusted-root/participants-list) has fully transitioned to Common CA Certificate Database (CCADB)

## Java

Planned support of `/usr/share/ca-certificates-java/ca-certificates-java.jar` on the system where `tlstrust` is run.

## Debian Linux (Including derivatives like Ubuntu)
## Redhat Enterprise Linux (RHEL)
## Open SUSE Linux
## Alpine Linux (Common for container based images)
## Arch Linux

These Linux distributions typically include a package named `update-ca-certificates` or similar and stored to `/etc/ssl/certs`, `/usr/share/ca-certificates`, and `/usr/local/share/ca-certificates`, or will require developers to install their own packages that supply a bundle of CA certificates that are used as the root trust store by most HTTP clients in software and programming languages.

Some clients behave specific to an installed package called `openssl`, or more specifically will use the same default `/etc/ssl/ca-bundle.pem` that is used by `openssl`.

There are alternatives to the main `openssl` package such as `glib-openssl` that will use the same common path as `openssl` to store it's own bundle; `/etc/ssl/ca-bundle.pem`.

For the purposes of evaluating trust for the Linux platform, `tlstrust` will embed the latest signatures from the `deb` distribution of `update-ca-certificates` combined with the `openssl` default. As different versions of any package may install any assortment of CA certificates in `/etc/ssl/ca-bundle.pem`, when evaluating platform trust for Linux `tlstrust` will embed the contents after an installation of the main `openssl` package and [latest](https://www.openssl.org/source/) Long Term Support (LTS) version.

Essentially; The results of Linux evaluation will be based on the latest Debian bundle and the default bundle of LTS `openssl` that will be present in any up-to-date distribution.

# Evaluations of trust for Web Browsers

The approach for all participating browsers will soon be standardized on the Common CA Certificate Database (CCADB).

Below is a pseudo knowledge base to help guide users of how results of using `tlstrust` are derived:

## Firefox

All evaluations of trust for Firefox will derive it's result using the Common CA Certificate Database (CCADB)

## Tor Browser

Firefox; All evaluations of trust for Firefox will derive it's result using the Common CA Certificate Database (CCADB)

## Chromium Web Browser

[Chrome Root Program](https://www.chromium.org/Home/chromium-security/root-ca-policy) as at Oct 2021 is in a transitional state, both the platform/operating system root trust store and the platform independent (and consistent across participating browsers) are both supported.

For this reason `tlstrust` will derive it's result from evaluations of trust for Chrome using the Common CA Certificate Database (CCADB).

## Google Chrome
## Microsoft Edge
## Brave
## Opera
## Vivaldi
## Amazon Silk
## Samsung Internet Browser
## Yandex Browser

Chromium-based; All evaluations of trust for Firefox will derive it's result using the Common CA Certificate Database (CCADB)

## Safari

The [macOS Trust Store](https://support.apple.com/en-gb/HT202858) contained trusted root certificates that are preinstalled with macOS and used by Safari.

The [iOS Trust Store](https://support.apple.com/en-gb/HT204132) contained trusted root certificates that are preinstalled with iOS and used by all web browsers that run on iOS (there are no exceptions, Apple simply do not allow any other browsers or overrides of critical features, such as root trust, on the iOS platform)

[Coming into effect December 1, 2021](https://www.apple.com/certificateauthority/ca_program.html) Apple will also use Common CA Certificate Database (CCADB) which will be enforced and used solely from April 1, 2022.

For this reason `tlstrust` will derive it's result from evaluations of trust for Safari evaluations using the Common CA Certificate Database (CCADB).

# Programming Language Trust (Microservice architecture and APIs)

Starting with Python

## Python native `http.client`

There are no Root CA Certificates that are trusted by default, it relies on `ssl.SSLContext` (or `ssl.create_default_context`) to be provided to the `HTTPSConnection` when TLS verification is used.

Therefore the methodology would be via [`SSLContext.load_default_certs()`](https://docs.python.org/3/library/ssl.html#ssl.SSLContext.load_default_certs) which `tlstrust` also needs to be asked which server Python is running on. Therefore native Python can be checked using:

## Python package `certifi`

Many Python packages (like `pyOpenSSL` that `tlstrust` uses) leverage a package called `certifi` for a consistent root trust evaluation across platforms.

While `certifi` is commonly believed to make the Mozilla Root CA Trust Store available to python, which it does, but `certifi` is it's own Root CA Trust Store because they further curate the Certificates to explicitly not trust any weak Certificates - and unfortunately suffers from being out-of-sync with updates to the Mozilla Root CA Trust Store.


## Python package `urllib`

Many Python popular packages (like `requests` where `certifi` originated) leverage a package called `urllib` for as common http client, and add a better developer experience on top.

While `urllib` is commonly believed to do it's own Root CA Trust Store checking, it actually uses `certifi` so `tlstrust` will alias `context.PYTHON_URLLIB` to `context.PYTHON_CERTIFI` until such a time this changes.


## Python package `requests`

The most popular package in python is `requests`.

Under `requests` is `urllib` for making HTTP clients, which in turn uses `certifi` for its Root CA Trust Store checking, So `tlstrust` will alias `context.PYTHON_REQUESTS` to `context.PYTHON_URLLIB` until such a time this changes.


## Python framework `django`

The most popular framework in python is `django`.

Similiar to `requests`; Under `django` is `urllib` for making HTTP clients, which in turn uses `certifi` for its Root CA Trust Store checking, So `tlstrust` will alias `context.PYTHON_DJANGO` to `context.PYTHON_URLLIB` until such a time this changes.

