import hashlib
from datetime import datetime
from OpenSSL.crypto import FILETYPE_ASN1, X509, FILETYPE_PEM, dump_certificate, load_certificate
from tlstrust import context
from tlstrust.stores.apple import SHA256_FINGERPRINTS as APPLE_FINGERPRINTS, COMMON_NAMES as APPLE_COMMON_NAMES
from tlstrust.stores.android import SHA1_FINGERPRINTS as ANDROID_FINGERPRINTS, COMMON_NAMES as ANDROID_COMMON_NAMES
from tlstrust.stores.ccadb import SHA1_FINGERPRINTS as CCADB_FINGERPRINTS, COMMON_NAMES as CCADB_COMMON_NAMES
from tlstrust.stores.java import SHA1_FINGERPRINTS as JAVA_FINGERPRINTS, COMMON_NAMES as JAVA_COMMON_NAMES
from tlstrust.stores.linux import SHA1_FINGERPRINTS as LINUX_FINGERPRINTS, COMMON_NAMES as LINUX_COMMON_NAMES
from tlstrust.stores.certifi import SHA1_FINGERPRINTS as CERTIFI_FINGERPRINTS, COMMON_NAMES as CERTIFI_COMMON_NAMES

__module__ = 'tlstrust'

class TrustStore:
    _certificate :X509
    ca_common_name :str
    fingerprint_sha1 :str
    fingerprint_sha256 :str

    def __init__(self, filetype :int = None, cacert :bytes = None, ca_common_name :str = None) -> bool:
        if ca_common_name is not None and not isinstance(ca_common_name, str):
            raise TypeError(f'ca_common_name type {type(ca_common_name)} not supported, expected str')
        if cacert is not None and not isinstance(cacert, bytes):
            raise TypeError(f'cacert type {type(cacert)} not supported, expected bytes')
        if filetype is not None and not isinstance(filetype, int):
            raise TypeError(f'filetype type {type(filetype)} not supported, expected OpenSSL.crypto.FILETYPE_PEM or OpenSSL.crypto.FILETYPE_ASN1')
        if filetype is not None and filetype not in [FILETYPE_ASN1, FILETYPE_PEM]:
            raise AttributeError('filetype type must be one of OpenSSL.crypto.FILETYPE_PEM or OpenSSL.crypto.FILETYPE_ASN1')
        if cacert is None and ca_common_name is None:
            raise AttributeError('Provide either the CA Certificate bytes or a CA Certificate subject common name')
        if filetype == FILETYPE_PEM:
            self._certificate = load_certificate(FILETYPE_PEM, cacert)
        if filetype == FILETYPE_ASN1:
            self._certificate = load_certificate(FILETYPE_ASN1, cacert)
        self.fingerprint_sha1 = None
        self.fingerprint_sha256 = None
        self.ca_common_name = None
        if isinstance(ca_common_name, str):
            self.ca_common_name = ca_common_name
        if hasattr(self, '_certificate') and isinstance(self._certificate, X509):
            der = dump_certificate(FILETYPE_ASN1, self._certificate)
            self.fingerprint_sha1 = hashlib.sha1(der).hexdigest().upper()
            fingerprint = hashlib.sha256(der).hexdigest()
            self.fingerprint_sha256 = ' '.join(
                fingerprint[i : i + 2] for i in range(0, len(fingerprint), 2)
            ).upper()

    @property
    def ccadb(self) -> bool:
        return self.fingerprint_sha1 in CCADB_FINGERPRINTS or self.ca_common_name in CCADB_COMMON_NAMES

    @property
    def apple(self) -> bool:
        return self.fingerprint_sha256 in APPLE_FINGERPRINTS or self.ca_common_name in APPLE_COMMON_NAMES

    @property
    def java(self) -> bool:
        return self.fingerprint_sha1 in JAVA_FINGERPRINTS or self.ca_common_name in JAVA_COMMON_NAMES

    @property
    def android(self) -> bool:
        return self.fingerprint_sha1 in ANDROID_FINGERPRINTS or self.ca_common_name in ANDROID_COMMON_NAMES

    @property
    def linux(self) -> bool:
        return self.fingerprint_sha1 in LINUX_FINGERPRINTS or self.ca_common_name in LINUX_COMMON_NAMES

    @property
    def certifi(self) -> bool:
        return self.fingerprint_sha1 in CERTIFI_FINGERPRINTS or self.ca_common_name in CERTIFI_COMMON_NAMES

    @property
    def is_trusted(self) -> bool:
        #TODO remove Apple Legacy support April 1, 2022
        apple_legacy = datetime.utcnow() < datetime(2021, 12, 1)
        evaluations = [self.ccadb, self.android, self.linux, self.certifi, self.java]
        if apple_legacy: evaluations.append(self.apple)
        return all(evaluations)

    def check(self, context_type :int = None) -> bool:
        if context_type is not None and not isinstance(context_type, int):
            raise TypeError(f'context type {type(context_type)} not supported, expected int')
        if context_type not in {None,context.SOURCE_CCADB,context.SOURCE_JAVA,context.SOURCE_APPLE,context.SOURCE_ANDROID,context.SOURCE_LINUX,context.SOURCE_CERTIFI}:
            raise AttributeError('context_type provided is invalid')
        #TODO remove Apple Legacy support April 1, 2022
        if context_type == context.SOURCE_APPLE and datetime.utcnow() >= datetime(2021, 12, 1):
            context_type = context.SOURCE_CCADB

        if context_type == context.SOURCE_CCADB:
            return self.ccadb
        if context_type == context.SOURCE_JAVA:
            return self.java
        if context_type == context.SOURCE_APPLE:
            return self.apple
        if context_type == context.SOURCE_ANDROID:
            return self.android
        if context_type == context.SOURCE_LINUX:
            return self.linux
        if context_type == context.SOURCE_CERTIFI:
            return self.certifi

        return self.is_trusted
