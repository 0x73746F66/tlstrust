from setuptools import setup, find_packages

setup(
    name="tlstrust",
    version="2.6.1",
    author='Christopher Langton',
    author_email='chris@langton.cloud',
    description="Utilities that assist with trust relationship checking of X.509 Certificates for various end-user devices with disparate root trust stores.",
    long_description="""
# tlstrust

Utilities that assist with trust relationship checking of X.509 Certificates for various end-user devices with disparate root trust stores.

![tlstrust cli](https://gitlab.com/trivialsec/tlstrust/-/raw/5052faa1d1a5fbf21dec6107622cffc58359762d/docs/images/tlstrust.jpg)

## [Documentation](https://gitlab.com/trivialsec/tlstrust/-/blob/main/docs/0.index.md)

On the command-line:

```sh
tlstrust --help
```

produces:

```
usage: tlstrust [-h] [-C CLIENT_PEM] [--disable-sni] [-O JSON_FILE] [-v] [-vv] [-vvv] [-vvvv] [--version] [targets ...]

positional arguments:
targets               All unnamed arguments are hosts (and ports) targets to test. ~$ tlstrust apple.com:443 github.io
localhost:3000

options:
-h, --help            show this help message and exit
-C CLIENT_PEM, --client-pem CLIENT_PEM
path to PEM encoded client certificate, url or file path accepted
--disable-sni         Do not negotiate SNI using INDA encoded host
-O JSON_FILE, --json-file JSON_FILE
Store to file as JSON
-v, --errors-only     set logging level to ERROR (default CRITICAL)
-vv, --warning        set logging level to WARNING (default CRITICAL)
-vvv, --info          set logging level to INFO (default CRITICAL)
-vvvv, --debug        set logging level to DEBUG (default CRITICAL)
--version
```

In your app you can:

```py
import os
from pathlib import Path
from OpenSSL.crypto import FILETYPE_ASN1
from tlstrust import TrustStore

der = Path(os.path.join(os.path.dirname(__file__), "cacert.der")).read_bytes()
trust_store = TrustStore(FILETYPE_ASN1, der)
print(trust_store.check_trust())
```

# Platform specific checking

```py
all_trusted = trust_store.check_trust()
assert all_trusted is True
assert trust_store.android
assert trust_store.linux
assert trust_store.ccadb # Windows, Mozilla, and Apple (from December 1st 2021)
assert trust_store.java
assert trust_store.certifi
```

## Basic usage

Using CCADB for demonstration purposes (includes Apple, Microsoft, and Mozilla)

```py
from tlstrust.context import SOURCE_CCADB

assert trust_store.exists(SOURCE_CCADB)
assert trust_store.expired_in_store(SOURCE_CCADB)
assert trust_store.get_certificate_from_store(SOURCE_CCADB)
assert trust_store.check_trust(SOURCE_CCADB)
```

## Other Platforms

```py
from tlstrust.context import PLATFORM_ANDROID
from tlstrust.context import PLATFORM_JAVA
from tlstrust.context import PLATFORM_LINUX
from tlstrust.context import PLATFORM_APPLE
```

## Apple (before CCADB)

Apple (legacy) Trust Store support exists in earlier versions of `tlstrust`, it was removed in version `2.0.0` so installing prior versions will allow you to access this functionality.

## Android versions

```py
from tlstrust.context import PLATFORM_ANDROID2_2
from tlstrust.context import PLATFORM_ANDROID2_3
from tlstrust.context import PLATFORM_ANDROID3
from tlstrust.context import PLATFORM_ANDROID4
from tlstrust.context import PLATFORM_ANDROID4_4
from tlstrust.context import PLATFORM_ANDROID7
from tlstrust.context import PLATFORM_ANDROID8
from tlstrust.context import PLATFORM_ANDROID9
from tlstrust.context import PLATFORM_ANDROID10
from tlstrust.context import PLATFORM_ANDROID11
from tlstrust.context import PLATFORM_ANDROID12
```

# Browser Trust Stores

```py
from tlstrust import context

assert trust_store.check_trust(context.BROWSER_AMAZON_SILK)
assert trust_store.check_trust(context.BROWSER_SAMSUNG_INTERNET_BROWSER)
assert trust_store.check_trust(context.BROWSER_GOOGLE_CHROME)
assert trust_store.check_trust(context.BROWSER_CHROMIUM)
assert trust_store.check_trust(context.BROWSER_FIREFOX)
assert trust_store.check_trust(context.BROWSER_BRAVE)
assert trust_store.check_trust(context.BROWSER_SAFARI)
assert trust_store.check_trust(context.BROWSER_MICROSOFT_EDGE)
assert trust_store.check_trust(context.BROWSER_YANDEX_BROWSER)
assert trust_store.check_trust(context.BROWSER_OPERA)
assert trust_store.check_trust(context.BROWSER_VIVALDI)
assert trust_store.check_trust(context.BROWSER_TOR_BROWSER)
```

# Programming Language Trust (Microservice architecture and APIs)

Python:

```py
from tlstrust import context

assert trust_store.check_trust(context.LANGUAGE_PYTHON_WINDOWS_SERVER)
assert trust_store.check_trust(context.LANGUAGE_PYTHON_LINUX_SERVER)
assert trust_store.check_trust(context.LANGUAGE_PYTHON_MACOS_SERVER)
assert trust_store.check_trust(context.LANGUAGE_PYTHON_CERTIFI)
assert trust_store.check_trust(context.LANGUAGE_PYTHON_URLLIB)
assert trust_store.check_trust(context.LANGUAGE_PYTHON_REQUESTS)
assert trust_store.check_trust(context.LANGUAGE_PYTHON_DJANGO)

Go:

```py
from tlstrust import context

assert trust_store.check_trust(context.LANGUAGE_GO_WINDOWS_SERVER)
assert trust_store.check_trust(context.LANGUAGE_GO_LINUX_SERVER)
assert trust_store.check_trust(context.LANGUAGE_GO_MACOS_SERVER)
assert trust_store.check_trust(context.LANGUAGE_GO_CERTIFI)
```

Node.js:

```py
from tlstrust import context

assert trust_store.check_trust(context.LANGUAGE_NODE_WINDOWS_SERVER)
assert trust_store.check_trust(context.LANGUAGE_NODE_LINUX_SERVER)
assert trust_store.check_trust(context.LANGUAGE_NODE_MACOS_SERVER)
assert trust_store.check_trust(context.LANGUAGE_NODE_CERTIFI)
```

Ruby:

```py
from tlstrust import context

assert trust_store.check_trust(context.LANGUAGE_RUBY_WINDOWS_SERVER)
assert trust_store.check_trust(context.LANGUAGE_RUBY_LINUX_SERVER)
assert trust_store.check_trust(context.LANGUAGE_RUBY_MACOS_SERVER)
assert trust_store.check_trust(context.LANGUAGE_RUBY_CERTIFI)
```

Erlang:

```py
from tlstrust import context

assert trust_store.check_trust(context.LANGUAGE_ERLANG_WINDOWS_SERVER)
assert trust_store.check_trust(context.LANGUAGE_ERLANG_LINUX_SERVER)
assert trust_store.check_trust(context.LANGUAGE_ERLANG_MACOS_SERVER)
assert trust_store.check_trust(context.LANGUAGE_ERLANG_CERTIFI)
```

Rust:

```py
from tlstrust import context

assert trust_store.check_trust(context.LANGUAGE_RUST_WINDOWS_SERVER)
assert trust_store.check_trust(context.LANGUAGE_RUST_LINUX_SERVER)
assert trust_store.check_trust(context.LANGUAGE_RUST_MACOS_SERVER)
assert trust_store.check_trust(context.LANGUAGE_RUST_RUSTLS)
assert trust_store.check_trust(context.LANGUAGE_RUST_WEBPKI)
```

## [Change Log](https://gitlab.com/trivialsec/tlstrust/-/blob/main/docs/z.change-log.md)
    """,
    long_description_content_type="text/markdown",
    url="https://gitlab.com/trivialsec/tlstrust",
    project_urls={
        "Source": "https://gitlab.com/trivialsec/tlstrust",
        "Documentation": "https://gitlab.com/trivialsec/tlstrust/-/blob/main/docs/0.index.md",
        "Tracker": "https://gitlab.com/trivialsec/tlstrust/-/issues",
    },
    classifiers=[
        "Operating System :: OS Independent",
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
    ],
    include_package_data=True,
    install_requires=[
        'certifi',
        'cryptography==35.0.0',
        'asn1crypto==1.4.0',
        'pyOpenSSL==21.0.0',
        'rich==12.0.0',
        'validators==0.18.2',
        'idna==3.3'
    ],
    entry_points = {
        'console_scripts': ['tlstrust=tlstrust.cli:cli'],
    },
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.9",
    options={"bdist_wheel": {"universal": "1"}},
)
