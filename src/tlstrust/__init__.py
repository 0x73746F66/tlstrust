import hashlib
from datetime import datetime
from OpenSSL.crypto import FILETYPE_ASN1, X509, FILETYPE_PEM, dump_certificate, load_certificate
from tlstrust import context
from tlstrust.stores.apple import SHA256_FINGERPRINTS as APPLE_FINGERPRINTS
from tlstrust.stores.android import SHA1_FINGERPRINTS as ANDROID_FINGERPRINTS
from tlstrust.stores.ccadb import SHA1_FINGERPRINTS as CCADB_FINGERPRINTS
from tlstrust.stores.java import SHA1_FINGERPRINTS as JAVA_FINGERPRINTS
from tlstrust.stores.linux import SHA1_FINGERPRINTS as LINUX_FINGERPRINTS
from tlstrust.stores.certifi import SHA1_FINGERPRINTS as CERTIFI_FINGERPRINTS

__module__ = 'tlstrust'

class TrustStore:
    _certificate :X509
    certificate_format :str
    fingerprint_sha1 :str
    fingerprint_sha256 :str
    ccadb :bool
    java :bool
    apple :bool
    android :bool
    linux :bool
    certifi :bool

    def __init__(self, filetype :int, cacert :bytes) -> bool:
        super().__init__()
        if filetype == FILETYPE_PEM:
            self._certificate = load_certificate(FILETYPE_PEM, cacert)
            self.certificate_format = 'PEM'
        if filetype == FILETYPE_ASN1:
            self._certificate = load_certificate(FILETYPE_ASN1, cacert)
            self.certificate_format = 'ASN1'
        der = dump_certificate(FILETYPE_ASN1, self._certificate)
        print(der)
        self.fingerprint_sha1 = hashlib.sha1(der).hexdigest().upper()
        fingerprint = hashlib.sha256(der).hexdigest()
        self.fingerprint_sha256 = ' '.join(
            fingerprint[i : i + 2] for i in range(0, len(fingerprint), 2)
        ).upper()

    def is_trusted(self, context_type :int = None) -> bool:
        if context_type is not None and not isinstance(context_type, int):
            raise TypeError(f'context type {type(context_type)} not supported, expected int')
        if context_type not in {None,context.SOURCE_CCADB,context.SOURCE_JAVA,context.SOURCE_APPLE,context.SOURCE_ANDROID,context.SOURCE_LINUX,context.SOURCE_CERTIFI}:
            raise AttributeError('context_type provided is invalid')
        #TODO remove Apple Legacy support April 1, 2022
        apple_legacy = context_type == context.SOURCE_APPLE and datetime.utcnow() < datetime(2021, 12, 1)
        if context_type == context.SOURCE_APPLE and not apple_legacy:
            context_type = context.SOURCE_CCADB
        self._is_trusted(context_type)
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
        evaluations = [self.ccadb, self.android, self.linux, self.certifi, self.java]
        if apple_legacy: evaluations.append(self.apple)
        return all(evaluations)

    def _is_trusted(self, context_type):
        context_type in {None,context.SOURCE_CCADB} and self.trusted_by_ccadb()
        context_type in {None,context.SOURCE_JAVA} and self.trusted_by_java()
        context_type in {None,context.SOURCE_APPLE} and self.trusted_by_apple()
        context_type in {None,context.SOURCE_ANDROID} and self.trusted_by_android()
        context_type in {None,context.SOURCE_LINUX} and self.trusted_by_linux()
        context_type in {None,context.SOURCE_CERTIFI} and self.trusted_by_certifi()

    def trusted_by_ccadb(self) -> bool:
        self.ccadb = self.fingerprint_sha1 in CCADB_FINGERPRINTS
        return self.ccadb

    def trusted_by_apple(self) -> bool:
        self.apple = self.fingerprint_sha256 in APPLE_FINGERPRINTS
        return self.apple

    def trusted_by_java(self) -> bool:
        self.java = self.fingerprint_sha1 in JAVA_FINGERPRINTS
        return self.java

    def trusted_by_android(self) -> bool:
        self.android = self.fingerprint_sha1 in ANDROID_FINGERPRINTS
        return self.android

    def trusted_by_linux(self) -> bool:
        self.linux = self.fingerprint_sha1 in LINUX_FINGERPRINTS
        return self.linux

    def trusted_by_certifi(self) -> bool:
        self.certifi = self.fingerprint_sha1 in CERTIFI_FINGERPRINTS
        return self.certifi
