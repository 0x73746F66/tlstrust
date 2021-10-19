import hashlib
from OpenSSL.crypto import FILETYPE_ASN1, X509, FILETYPE_PEM, dump_certificate, load_certificate
from tlstrust.apple import SHA256_FINGERPRINTS as APPLE_FINGERPRINTS
from tlstrust.android import SHA1_FINGERPRINTS as ANDROID_FINGERPRINTS
from tlstrust.ccadb import SHA1_FINGERPRINTS as CCADB_FINGERPRINTS
from tlstrust.java import SHA1_FINGERPRINTS as JAVA_FINGERPRINTS
from tlstrust.linux import SHA1_FINGERPRINTS as LINUX_FINGERPRINTS

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

    def is_trusted(self, context :int = None) -> bool:
        if context is not None and not isinstance(context, int):
            raise TypeError(f'context type {type(context)} not supported, expected int')

        if context in {None,0,1,2,3,4}:
            context in {None,0} and self.trusted_by_ccadb()
            context in {None,1} and self.trusted_by_apple()
            context in {None,2} and self.trusted_by_java()
            context in {None,3} and self.trusted_by_android()
            context in {None,4} and self.trusted_by_linux()

        if context == 0:
            return self.ccadb
        if context == 1:
            return self.apple
        if context == 2:
            return self.java
        if context == 3:
            return self.android
        if context == 4:
            return self.linux

        return all([self.ccadb, self.apple, self.android, self.linux])

    def trusted_by_ccadb(self) -> bool:
        self.ccadb = self.fingerprint_sha1 in CCADB_FINGERPRINTS
        return self.ccadb

    def trusted_by_apple(self) -> bool:
        self.apple = self.fingerprint_sha256 in APPLE_FINGERPRINTS
        return self.apple

    def trusted_by_java(self) -> bool:
        self.java = True
        return self.java

    def trusted_by_android(self) -> bool:
        self.android = self.fingerprint_sha1 in ANDROID_FINGERPRINTS
        return self.android

    def trusted_by_linux(self) -> bool:
        self.linux = self.fingerprint_sha1 in LINUX_FINGERPRINTS
        return self.linux
