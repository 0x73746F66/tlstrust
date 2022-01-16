
import sys
import logging
from binascii import hexlify
from OpenSSL.crypto import X509, FILETYPE_PEM, load_certificate
from cryptography.x509.extensions import SubjectKeyIdentifier
from tlstrust import context
from tlstrust.stores.android_2_2 import UNTRUSTED as ANDROID2_2_UNTRUSTED, PEM_FILES as ANDROID2_2_PEM_FILES
from tlstrust.stores.android_2_3 import UNTRUSTED as ANDROID2_3_UNTRUSTED, PEM_FILES as ANDROID2_3_PEM_FILES
from tlstrust.stores.android_3 import UNTRUSTED as ANDROID3_UNTRUSTED, PEM_FILES as ANDROID3_PEM_FILES
from tlstrust.stores.android_4_4 import UNTRUSTED as ANDROID4_4_UNTRUSTED, PEM_FILES as ANDROID4_4_PEM_FILES
from tlstrust.stores.android_4 import UNTRUSTED as ANDROID4_UNTRUSTED, PEM_FILES as ANDROID4_PEM_FILES
from tlstrust.stores.android_7 import UNTRUSTED as ANDROID7_UNTRUSTED, PEM_FILES as ANDROID7_PEM_FILES
from tlstrust.stores.android_8 import UNTRUSTED as ANDROID8_UNTRUSTED, PEM_FILES as ANDROID8_PEM_FILES
from tlstrust.stores.android_9 import UNTRUSTED as ANDROID9_UNTRUSTED, PEM_FILES as ANDROID9_PEM_FILES
from tlstrust.stores.android_10 import UNTRUSTED as ANDROID10_UNTRUSTED, PEM_FILES as ANDROID10_PEM_FILES
from tlstrust.stores.android_11 import UNTRUSTED as ANDROID11_UNTRUSTED, PEM_FILES as ANDROID11_PEM_FILES
from tlstrust.stores.android_12 import UNTRUSTED as ANDROID12_UNTRUSTED, PEM_FILES as ANDROID12_PEM_FILES
from tlstrust.stores.android_latest import UNTRUSTED as ANDROID_UNTRUSTED, PEM_FILES as ANDROID_PEM_FILES
from tlstrust.stores.ccadb import UNTRUSTED as CCADB_UNTRUSTED, PEM_FILES as CCADB_PEM_FILES
from tlstrust.stores.java import UNTRUSTED as JAVA_UNTRUSTED, PEM_FILES as JAVA_PEM_FILES
from tlstrust.stores.linux import UNTRUSTED as LINUX_UNTRUSTED, PEM_FILES as LINUX_PEM_FILES
from tlstrust.stores.certifi import UNTRUSTED as CERTIFI_UNTRUSTED, PEM_FILES as CERTIFI_PEM_FILES

__module__ = 'tlstrust'
__version__ = '2.0.4'

assert sys.version_info >= (3, 9), "Requires Python 3.9 or newer"

logger = logging.getLogger(__name__)
DEPRECATION_MESSAGE = 'Apple legacy supports will be removed April 1, 2022'
MISSING_MESSAGE = 'Certificate does not exist'

class TrustStore:
    key_identifier :str

    def __init__(self, authority_key_identifier :str) -> bool:
        if not isinstance(authority_key_identifier, str):
            raise TypeError(f'authority_key_identifier type {type(authority_key_identifier)} not supported, expected str')
        # used for Root CA matching, SKI is authoritative
        self.key_identifier = authority_key_identifier
        for ctx in [context.SOURCE_CCADB, context.SOURCE_CERTIFI, context.SOURCE_ANDROID, context.SOURCE_JAVA, context.SOURCE_LINUX, context.PLATFORM_ANDROID12, context.PLATFORM_ANDROID11, context.PLATFORM_ANDROID10, context.PLATFORM_ANDROID9, context.PLATFORM_ANDROID8, context.PLATFORM_ANDROID7, context.PLATFORM_ANDROID4_4, context.PLATFORM_ANDROID4, context.PLATFORM_ANDROID3, context.PLATFORM_ANDROID2_3, context.PLATFORM_ANDROID2_2]:
            if self.exists(context_type=ctx):
                break

    def match_certificate(self, root_ca :X509) -> bool:
        return any(
            isinstance(ext.value, SubjectKeyIdentifier) and self.key_identifier == hexlify(ext.value.key_identifier).decode('utf-8')
            for ext in root_ca.to_cryptography().extensions
        )

    @property
    def ccadb(self) -> bool:
        return self.key_identifier not in CCADB_UNTRUSTED and self.key_identifier in CCADB_PEM_FILES.keys()

    @property
    def java(self) -> bool:
        return self.key_identifier not in JAVA_UNTRUSTED and self.key_identifier in JAVA_PEM_FILES.keys()

    @property
    def android(self) -> bool:
        untrusted = list(set(ANDROID_UNTRUSTED + ANDROID2_2_UNTRUSTED + ANDROID2_3_UNTRUSTED + ANDROID3_UNTRUSTED + ANDROID4_UNTRUSTED + ANDROID4_4_UNTRUSTED + ANDROID7_UNTRUSTED + ANDROID8_UNTRUSTED + ANDROID9_UNTRUSTED + ANDROID10_UNTRUSTED + ANDROID11_UNTRUSTED + ANDROID12_UNTRUSTED))
        files = ANDROID_PEM_FILES | ANDROID2_2_PEM_FILES | ANDROID2_3_PEM_FILES | ANDROID3_PEM_FILES | ANDROID4_PEM_FILES | ANDROID4_4_PEM_FILES | ANDROID7_PEM_FILES | ANDROID8_PEM_FILES | ANDROID9_PEM_FILES | ANDROID10_PEM_FILES | ANDROID11_PEM_FILES | ANDROID12_PEM_FILES
        return self.key_identifier not in untrusted and self.key_identifier in set(files.keys())

    @property
    def android_latest(self) -> bool:
        return self.key_identifier not in ANDROID_UNTRUSTED and self.key_identifier in ANDROID_PEM_FILES.keys()

    @property
    def android12(self) -> bool:
        return self.key_identifier not in ANDROID12_UNTRUSTED and self.key_identifier in ANDROID12_PEM_FILES.keys()

    @property
    def android11(self) -> bool:
        return self.key_identifier not in ANDROID11_UNTRUSTED and self.key_identifier in ANDROID11_PEM_FILES.keys()

    @property
    def android10(self) -> bool:
        return self.key_identifier not in ANDROID10_UNTRUSTED and self.key_identifier in ANDROID10_PEM_FILES.keys()

    @property
    def android9(self) -> bool:
        return self.key_identifier not in ANDROID9_UNTRUSTED and self.key_identifier in ANDROID9_PEM_FILES.keys()

    @property
    def android8(self) -> bool:
        return self.key_identifier not in ANDROID8_UNTRUSTED and self.key_identifier in ANDROID8_PEM_FILES.keys()

    @property
    def android7(self) -> bool:
        return self.key_identifier not in ANDROID7_UNTRUSTED and self.key_identifier in ANDROID7_PEM_FILES.keys()

    @property
    def android4_4(self) -> bool:
        return self.key_identifier not in ANDROID4_4_UNTRUSTED and self.key_identifier in ANDROID4_4_PEM_FILES.keys()

    @property
    def android4(self) -> bool:
        return self.key_identifier not in ANDROID4_UNTRUSTED and self.key_identifier in ANDROID4_PEM_FILES.keys()

    @property
    def android3(self) -> bool:
        return self.key_identifier not in ANDROID3_UNTRUSTED and self.key_identifier in ANDROID3_PEM_FILES.keys()

    @property
    def android2_3(self) -> bool:
        return self.key_identifier not in ANDROID2_3_UNTRUSTED and self.key_identifier in ANDROID2_3_PEM_FILES.keys()

    @property
    def android2_2(self) -> bool:
        return self.key_identifier not in ANDROID2_2_UNTRUSTED and self.key_identifier in ANDROID2_2_PEM_FILES.keys()

    @property
    def linux(self) -> bool:
        return self.key_identifier not in LINUX_UNTRUSTED and self.key_identifier in LINUX_PEM_FILES.keys()

    @property
    def certifi(self) -> bool:
        return self.key_identifier not in CERTIFI_UNTRUSTED and self.key_identifier in CERTIFI_PEM_FILES.keys()

    @property
    def is_trusted(self) -> bool:
        return all([self.ccadb, self.android, self.linux, self.certifi, self.java])

    @staticmethod
    def valid_context_type(context_type :int) -> bool:
        return context_type in {None,context.SOURCE_CCADB,context.SOURCE_JAVA,context.SOURCE_ANDROID,context.SOURCE_LINUX,context.SOURCE_CERTIFI,context.PLATFORM_ANDROID12,context.PLATFORM_ANDROID11,context.PLATFORM_ANDROID10,context.PLATFORM_ANDROID9,context.PLATFORM_ANDROID8,context.PLATFORM_ANDROID7,context.PLATFORM_ANDROID4_4,context.PLATFORM_ANDROID4,context.PLATFORM_ANDROID3,context.PLATFORM_ANDROID2_3,context.PLATFORM_ANDROID2_2}

    def exists(self, context_type :int) -> bool:
        if not TrustStore.valid_context_type(context_type):
            raise AttributeError(context.INVALID_CONTEXT)

        if context_type == context.SOURCE_CCADB and self.key_identifier in CCADB_PEM_FILES.keys():
            return self.match_certificate(self.get_certificate_from_store(context.SOURCE_CCADB))
        if context_type == context.SOURCE_JAVA and self.key_identifier in JAVA_PEM_FILES.keys():
            return self.match_certificate(self.get_certificate_from_store(context.SOURCE_JAVA))
        if context_type == context.SOURCE_ANDROID and self.key_identifier in ANDROID_PEM_FILES.keys():
            return self.match_certificate(self.get_certificate_from_store(context.SOURCE_ANDROID))
        if context_type == context.SOURCE_LINUX and self.key_identifier in LINUX_PEM_FILES.keys():
            return self.match_certificate(self.get_certificate_from_store(context.SOURCE_LINUX))
        if context_type == context.SOURCE_CERTIFI and self.key_identifier in CERTIFI_PEM_FILES.keys():
            return self.match_certificate(self.get_certificate_from_store(context.SOURCE_CERTIFI))
        if context_type == context.PLATFORM_ANDROID12 and self.key_identifier in ANDROID12_PEM_FILES.keys():
            return self.match_certificate(self.get_certificate_from_store(context.PLATFORM_ANDROID12))
        if context_type == context.PLATFORM_ANDROID11 and self.key_identifier in ANDROID11_PEM_FILES.keys():
            return self.match_certificate(self.get_certificate_from_store(context.PLATFORM_ANDROID11))
        if context_type == context.PLATFORM_ANDROID10 and self.key_identifier in ANDROID10_PEM_FILES.keys():
            return self.match_certificate(self.get_certificate_from_store(context.PLATFORM_ANDROID10))
        if context_type == context.PLATFORM_ANDROID9 and self.key_identifier in ANDROID9_PEM_FILES.keys():
            return self.match_certificate(self.get_certificate_from_store(context.PLATFORM_ANDROID9))
        if context_type == context.PLATFORM_ANDROID8 and self.key_identifier in ANDROID8_PEM_FILES.keys():
            return self.match_certificate(self.get_certificate_from_store(context.PLATFORM_ANDROID8))
        if context_type == context.PLATFORM_ANDROID7 and self.key_identifier in ANDROID7_PEM_FILES.keys():
            return self.match_certificate(self.get_certificate_from_store(context.PLATFORM_ANDROID7))
        if context_type == context.PLATFORM_ANDROID4_4 and self.key_identifier in ANDROID4_4_PEM_FILES.keys():
            return self.match_certificate(self.get_certificate_from_store(context.PLATFORM_ANDROID7))
        if context_type == context.PLATFORM_ANDROID4 and self.key_identifier in ANDROID4_PEM_FILES.keys():
            return self.match_certificate(self.get_certificate_from_store(context.PLATFORM_ANDROID7))
        if context_type == context.PLATFORM_ANDROID3 and self.key_identifier in ANDROID3_PEM_FILES.keys():
            return self.match_certificate(self.get_certificate_from_store(context.PLATFORM_ANDROID7))
        if context_type == context.PLATFORM_ANDROID2_3 and self.key_identifier in ANDROID2_3_PEM_FILES.keys():
            return self.match_certificate(self.get_certificate_from_store(context.PLATFORM_ANDROID7))
        if context_type == context.PLATFORM_ANDROID2_2 and self.key_identifier in ANDROID2_2_PEM_FILES.keys():
            return self.match_certificate(self.get_certificate_from_store(context.PLATFORM_ANDROID7))
        return False

    def expired_in_store(self, context_type :int) -> bool:
        if not TrustStore.valid_context_type(context_type):
            raise AttributeError(context.INVALID_CONTEXT)
        if not self.exists(context_type=context_type):
            raise FileExistsError('Certificate does not exist')
        return self.get_certificate_from_store(context_type=context_type).has_expired()

    def get_certificate_from_store(self, context_type :int) -> X509:
        if not TrustStore.valid_context_type(context_type):
            raise AttributeError(context.INVALID_CONTEXT)
        certificate = None
        try:
            if context_type == context.SOURCE_CCADB:
                certificate = load_certificate(FILETYPE_PEM, CCADB_PEM_FILES[self.key_identifier].encode())
            if context_type == context.SOURCE_ANDROID:
                certificate = load_certificate(FILETYPE_PEM, ANDROID_PEM_FILES[self.key_identifier].encode())
            if context_type == context.SOURCE_JAVA:
                certificate = load_certificate(FILETYPE_PEM, JAVA_PEM_FILES[self.key_identifier].encode())
            if context_type == context.SOURCE_LINUX:
                certificate = load_certificate(FILETYPE_PEM, LINUX_PEM_FILES[self.key_identifier].encode())
            if context_type == context.SOURCE_CERTIFI:
                certificate = load_certificate(FILETYPE_PEM, CERTIFI_PEM_FILES[self.key_identifier].encode())
            if context_type == context.PLATFORM_ANDROID2_2:
                certificate = load_certificate(FILETYPE_PEM, ANDROID2_2_PEM_FILES[self.key_identifier].encode())
            if context_type == context.PLATFORM_ANDROID2_3:
                certificate = load_certificate(FILETYPE_PEM, ANDROID2_3_PEM_FILES[self.key_identifier].encode())
            if context_type == context.PLATFORM_ANDROID3:
                certificate = load_certificate(FILETYPE_PEM, ANDROID3_PEM_FILES[self.key_identifier].encode())
            if context_type == context.PLATFORM_ANDROID4:
                certificate = load_certificate(FILETYPE_PEM, ANDROID4_PEM_FILES[self.key_identifier].encode())
            if context_type == context.PLATFORM_ANDROID4_4:
                certificate = load_certificate(FILETYPE_PEM, ANDROID4_4_PEM_FILES[self.key_identifier].encode())
            if context_type == context.PLATFORM_ANDROID7:
                certificate = load_certificate(FILETYPE_PEM, ANDROID7_PEM_FILES[self.key_identifier].encode())
            if context_type == context.PLATFORM_ANDROID8:
                certificate = load_certificate(FILETYPE_PEM, ANDROID8_PEM_FILES[self.key_identifier].encode())
            if context_type == context.PLATFORM_ANDROID9:
                certificate = load_certificate(FILETYPE_PEM, ANDROID9_PEM_FILES[self.key_identifier].encode())
            if context_type == context.PLATFORM_ANDROID10:
                certificate = load_certificate(FILETYPE_PEM, ANDROID10_PEM_FILES[self.key_identifier].encode())
            if context_type == context.PLATFORM_ANDROID11:
                certificate = load_certificate(FILETYPE_PEM, ANDROID11_PEM_FILES[self.key_identifier].encode())
            if context_type == context.PLATFORM_ANDROID12:
                certificate = load_certificate(FILETYPE_PEM, ANDROID12_PEM_FILES[self.key_identifier].encode())
        except KeyError:
            pass
        except Exception as ex:
            raise AttributeError(MISSING_MESSAGE) from ex
        if certificate is None or not self.match_certificate(certificate):
            raise FileExistsError(MISSING_MESSAGE)
        return certificate

    def check_trust(self, context_type :int = None) -> bool:
        if context_type is not None and not isinstance(context_type, int):
            raise TypeError(f'context type {type(context_type)} not supported, expected int')
        if not TrustStore.valid_context_type(context_type):
            raise AttributeError(context.INVALID_CONTEXT)

        if context_type == context.SOURCE_CCADB:
            return self.ccadb
        if context_type == context.SOURCE_JAVA:
            return self.java
        if context_type == context.SOURCE_ANDROID:
            return self.android
        if context_type == context.PLATFORM_ANDROID12:
            return self.android12
        if context_type == context.PLATFORM_ANDROID11:
            return self.android11
        if context_type == context.PLATFORM_ANDROID10:
            return self.android10
        if context_type == context.PLATFORM_ANDROID9:
            return self.android9
        if context_type == context.PLATFORM_ANDROID8:
            return self.android8
        if context_type == context.PLATFORM_ANDROID7:
            return self.android7
        if context_type == context.PLATFORM_ANDROID4_4:
            return self.android4_4
        if context_type == context.PLATFORM_ANDROID4:
            return self.android4
        if context_type == context.PLATFORM_ANDROID3:
            return self.android3
        if context_type == context.PLATFORM_ANDROID2_3:
            return self.android2_3
        if context_type == context.PLATFORM_ANDROID2_2:
            return self.android2_2
        if context_type == context.SOURCE_LINUX:
            return self.linux
        if context_type == context.SOURCE_CERTIFI:
            return self.certifi

        return self.is_trusted
