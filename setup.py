from setuptools import setup, find_packages

setup(
    name="tlstrust",
    version="0.3.0",
    author='Christopher Langton',
    author_email='chris@langton.cloud',
    description="Utilities that assist with trust relationship checking of X.509 Certificates for various end-user devices with disparate root trust stores.",
    long_description="""
# tlstrust

Utilities that assist with trust relationship checking of X.509 Certificates for various end-user devices with disparate root trust stores.

## [Documentation](https://gitlab.com/chrislangton/py-tls-trust/-/blob/main/docs/0.index.md)

In your app you can:

```py
import os
from pathlib import Path
from OpenSSL.crypto import FILETYPE_ASN1
from tlstrust import TrustStore

der = Path(os.path.join(os.path.dirname(__file__), "cacert.der")).read_bytes()
trust_store = TrustStore(FILETYPE_ASN1, der)
print(trust_store.is_trusted())
```

# Platform specific checking

```py
all_trusted = trust_store.is_trusted()
assert all_trusted is True
assert trust_store.apple # Until December 1st 2021
assert trust_store.android
assert trust_store.linux
assert trust_store.ccadb # Windows, Mozilla, and Apple (from December 1st 2021)
assert trust_store.java
assert trust_store.certifi
```

## Windows only

```py
from tlstrust.context import PLATFORM_WINDOWS

assert trust_store.is_trusted(PLATFORM_WINDOWS)
```

## Android only

```py
from tlstrust.context import PLATFORM_ANDROID

assert trust_store.is_trusted(PLATFORM_ANDROID)
```

## Java only

```py
from tlstrust.context import PLATFORM_JAVA

assert trust_store.is_trusted(PLATFORM_JAVA)
```

## Apple only

```py
from tlstrust.context import PLATFORM_APPLE

assert trust_store.is_trusted(PLATFORM_APPLE)
```

## Linux only

```py
from tlstrust.context import PLATFORM_WINDOWS

assert trust_store.is_trusted(PLATFORM_LINUX)
```

# Browser Trust Stores

```py
from tlstrust.context import BROWSER_AMAZON_SILK, BROWSER_SAMSUNG_INTERNET_BROWSER, BROWSER_GOOGLE_CHROME, BROWSER_CHROMIUM, BROWSER_FIREFOX, BROWSER_BRAVE, BROWSER_SAFARI, BROWSER_MICROSOFT_EDGE, BROWSER_YANDEX_BROWSER, BROWSER_OPERA, BROWSER_VIVALDI, BROWSER_TOR_BROWSER

assert trust_store.is_trusted(BROWSER_AMAZON_SILK)
assert trust_store.is_trusted(BROWSER_SAMSUNG_INTERNET_BROWSER)
assert trust_store.is_trusted(BROWSER_GOOGLE_CHROME)
assert trust_store.is_trusted(BROWSER_CHROMIUM)
assert trust_store.is_trusted(BROWSER_FIREFOX)
assert trust_store.is_trusted(BROWSER_BRAVE)
assert trust_store.is_trusted(BROWSER_SAFARI)
assert trust_store.is_trusted(BROWSER_MICROSOFT_EDGE)
assert trust_store.is_trusted(BROWSER_YANDEX_BROWSER)
assert trust_store.is_trusted(BROWSER_OPERA)
assert trust_store.is_trusted(BROWSER_VIVALDI)
assert trust_store.is_trusted(BROWSER_TOR_BROWSER)
```

# Programming Language Trust (Microservice architecture and APIs)

Python:

```py
from tlstrust.context import PYTHON_WINDOWS_SERVER, PYTHON_LINUX_SERVER, PYTHON_MACOS_SERVER, PYTHON_CERTIFI, PYTHON_URLLIB, PYTHON_REQUESTS, PYTHON_DJANGO

assert trust_store.is_trusted(PYTHON_WINDOWS_SERVER)
assert trust_store.is_trusted(PYTHON_LINUX_SERVER)
assert trust_store.is_trusted(PYTHON_MACOS_SERVER)
assert trust_store.is_trusted(PYTHON_CERTIFI)
assert trust_store.is_trusted(PYTHON_URLLIB)
assert trust_store.is_trusted(PYTHON_REQUESTS)
assert trust_store.is_trusted(PYTHON_DJANGO)
```

## [Change Log](https://gitlab.com/chrislangton/py-tls-trust/-/blob/main/docs/z.change-log.md)
    """,
    long_description_content_type="text/markdown",
    url="https://gitlab.com/chrislangton/py-tls-trust",
    project_urls={
        "Source": "https://gitlab.com/chrislangton/py-tls-trust",
        "Documentation": "https://gitlab.com/chrislangton/py-tls-trust/-/blob/main/docs/0.index.md",
        "Tracker": "https://gitlab.com/chrislangton/py-tls-trust/-/issues",
    },
    classifiers=[
        "Operating System :: OS Independent",
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
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
    python_requires=">=3.8",
    options={"bdist_wheel": {"universal": "1"}},
)
