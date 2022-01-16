from setuptools import setup, find_packages

setup(
    name="tlstrust",
    version="2.0.4",
    author='Christopher Langton',
    author_email='chris@langton.cloud',
    description="Utilities that assist with trust relationship checking of X.509 Certificates for various end-user devices with disparate root trust stores.",
    long_description="""
# tlstrust

Utilities that assist with trust relationship checking of X.509 Certificates for various end-user devices with disparate root trust stores.

## [Documentation](https://gitlab.com/trivialsec/tlstrust/-/blob/main/docs/0.index.md)

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
from tlstrust.context import BROWSER_AMAZON_SILK, BROWSER_SAMSUNG_INTERNET_BROWSER, BROWSER_GOOGLE_CHROME, BROWSER_CHROMIUM, BROWSER_FIREFOX, BROWSER_BRAVE, BROWSER_SAFARI, BROWSER_MICROSOFT_EDGE, BROWSER_YANDEX_BROWSER, BROWSER_OPERA, BROWSER_VIVALDI, BROWSER_TOR_BROWSER

assert trust_store.check_trust(BROWSER_AMAZON_SILK)
assert trust_store.check_trust(BROWSER_SAMSUNG_INTERNET_BROWSER)
assert trust_store.check_trust(BROWSER_GOOGLE_CHROME)
assert trust_store.check_trust(BROWSER_CHROMIUM)
assert trust_store.check_trust(BROWSER_FIREFOX)
assert trust_store.check_trust(BROWSER_BRAVE)
assert trust_store.check_trust(BROWSER_SAFARI)
assert trust_store.check_trust(BROWSER_MICROSOFT_EDGE)
assert trust_store.check_trust(BROWSER_YANDEX_BROWSER)
assert trust_store.check_trust(BROWSER_OPERA)
assert trust_store.check_trust(BROWSER_VIVALDI)
assert trust_store.check_trust(BROWSER_TOR_BROWSER)
```

# Programming Language Trust (Microservice architecture and APIs)

Python:

```py
from tlstrust.context import PYTHON_WINDOWS_SERVER, PYTHON_LINUX_SERVER, PYTHON_MACOS_SERVER, PYTHON_CERTIFI, PYTHON_URLLIB, PYTHON_REQUESTS, PYTHON_DJANGO

assert trust_store.check_trust(PYTHON_WINDOWS_SERVER)
assert trust_store.check_trust(PYTHON_LINUX_SERVER)
assert trust_store.check_trust(PYTHON_MACOS_SERVER)
assert trust_store.check_trust(PYTHON_CERTIFI)
assert trust_store.check_trust(PYTHON_URLLIB)
assert trust_store.check_trust(PYTHON_REQUESTS)
assert trust_store.check_trust(PYTHON_DJANGO)
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
        'certifi==2021.5.30',
        'cryptography==35.0.0',
        'asn1crypto==1.4.0',
        'pyOpenSSL==21.0.0'
    ],
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.9",
    options={"bdist_wheel": {"universal": "1"}},
)
