from setuptools import setup, find_packages

setup(
    name="tlstrust",
    version="0.0.1",
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

der = Path(os.path.join(os.path.dirname(__file__), "cert.der")).read_bytes()
trust_store = TrustStore()
print(trust_store.is_trusted(FILETYPE_ASN1, der))
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
    python_requires=">=3.9",
    options={"bdist_wheel": {"universal": "1"}},
)
