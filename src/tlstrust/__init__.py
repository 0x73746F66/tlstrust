import logging
from datetime import datetime
from binascii import hexlify
from OpenSSL.crypto import FILETYPE_ASN1, X509, FILETYPE_PEM, load_certificate
from cryptography.x509.extensions import SubjectKeyIdentifier
from tlstrust import context
from tlstrust.stores.apple import UNTRUSTED as APPLE_UNTRUSTED, REFERENCE_DATA
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
__version__ = '1.1.1'

logger = logging.getLogger(__name__)
DEPRECATION_MESSAGE = 'Apple legacy supports will be removed April 1, 2022'
MISSING_MESSAGE = 'Certificate does not exist'
APPLE_DATE_FMT = '%H:%M:%S %d %b %Y'
APPLE_KEY_CA_CN = 'Certificate name'
APPLE_KEY_EXPIRES = 'Expires'

class TrustStore:
    ca_common_name :str
    authority_key_identifier :str
    subject_key_identifier :str

    def __init__(self, ca_common_name :str, authority_key_identifier :str = None) -> bool:
        if not isinstance(ca_common_name, str):
            raise TypeError(f'ca_common_name type {type(ca_common_name)} not supported, expected str')
        # Require for Root CA cert lookups
        self.ca_common_name = ca_common_name
        if authority_key_identifier is not None and not isinstance(authority_key_identifier, str):
            raise TypeError(f'authority_key_identifier type {type(authority_key_identifier)} not supported, expected str')
        # Optional: may be used for Root CA matching, though the issuer common name should be unique or it wouldn't be compliant
        self.authority_key_identifier = authority_key_identifier
        for ctx in [context.SOURCE_CCADB, context.SOURCE_CERTIFI, context.SOURCE_ANDROID, context.SOURCE_APPLE, context.SOURCE_JAVA, context.SOURCE_LINUX, context.PLATFORM_ANDROID12, context.PLATFORM_ANDROID11, context.PLATFORM_ANDROID10, context.PLATFORM_ANDROID9, context.PLATFORM_ANDROID8, context.PLATFORM_ANDROID7]:
            if self.exists(context_type=ctx):
                break

    def match_certificate(self, root_ca :X509) -> bool:
        ski = None
        for ext in root_ca.to_cryptography().extensions:
            if isinstance(ext.value, SubjectKeyIdentifier):
                ski = hexlify(ext.value.key_identifier).decode('utf-8')
                break
        if self.authority_key_identifier is None or ski == self.authority_key_identifier:
            self.subject_key_identifier = ski
            return True
        return False

    @property
    def ccadb(self) -> bool:
        return self.ca_common_name not in CCADB_UNTRUSTED and self.ca_common_name in CCADB_PEM_FILES.keys()

    @property
    def apple(self) -> bool:
        logger.warning(DeprecationWarning(DEPRECATION_MESSAGE), exc_info=True)
        return self.ca_common_name not in APPLE_UNTRUSTED and self.ca_common_name in [data.get(APPLE_KEY_CA_CN).strip() for data in REFERENCE_DATA if self.ca_common_name == data.get(APPLE_KEY_CA_CN).strip() and datetime.utcnow() < datetime.strptime(data.get(APPLE_KEY_EXPIRES), APPLE_DATE_FMT)]

    @property
    def java(self) -> bool:
        return self.ca_common_name not in JAVA_UNTRUSTED and self.ca_common_name in JAVA_PEM_FILES.keys()

    @property
    def android(self) -> bool:
        untrusted = list(set(ANDROID_UNTRUSTED + ANDROID7_UNTRUSTED + ANDROID8_UNTRUSTED + ANDROID9_UNTRUSTED + ANDROID10_UNTRUSTED + ANDROID11_UNTRUSTED + ANDROID12_UNTRUSTED))
        files = ANDROID_PEM_FILES | ANDROID7_PEM_FILES | ANDROID8_PEM_FILES | ANDROID9_PEM_FILES | ANDROID10_PEM_FILES | ANDROID11_PEM_FILES | ANDROID12_PEM_FILES
        return self.ca_common_name not in untrusted and self.ca_common_name in set(files.keys())

    @property
    def android_latest(self) -> bool:
        return self.ca_common_name not in ANDROID_UNTRUSTED and self.ca_common_name in ANDROID_PEM_FILES.keys()

    @property
    def android12(self) -> bool:
        return self.ca_common_name not in ANDROID12_UNTRUSTED and self.ca_common_name in ANDROID12_PEM_FILES.keys()

    @property
    def android11(self) -> bool:
        return self.ca_common_name not in ANDROID11_UNTRUSTED and self.ca_common_name in ANDROID11_PEM_FILES.keys()

    @property
    def android10(self) -> bool:
        return self.ca_common_name not in ANDROID10_UNTRUSTED and self.ca_common_name in ANDROID10_PEM_FILES.keys()

    @property
    def android9(self) -> bool:
        return self.ca_common_name not in ANDROID9_UNTRUSTED and self.ca_common_name in ANDROID9_PEM_FILES.keys()

    @property
    def android8(self) -> bool:
        return self.ca_common_name not in ANDROID8_UNTRUSTED and self.ca_common_name in ANDROID8_PEM_FILES.keys()

    @property
    def android7(self) -> bool:
        return self.ca_common_name not in ANDROID7_UNTRUSTED and self.ca_common_name in ANDROID7_PEM_FILES.keys()

    @property
    def linux(self) -> bool:
        return self.ca_common_name not in LINUX_UNTRUSTED and self.ca_common_name in LINUX_PEM_FILES.keys()

    @property
    def certifi(self) -> bool:
        return self.ca_common_name not in CERTIFI_UNTRUSTED and self.ca_common_name in CERTIFI_PEM_FILES.keys()

    @property
    def is_trusted(self) -> bool:
        apple_legacy = datetime.utcnow() < datetime(2021, 12, 1)
        evaluations = [self.ccadb, self.android, self.linux, self.certifi, self.java]
        if apple_legacy: evaluations.append(self.apple)
        return all(evaluations)

    @staticmethod
    def valid_context_type(context_type :int) -> bool:
        return context_type in {None,context.SOURCE_CCADB,context.SOURCE_JAVA,context.SOURCE_APPLE,context.SOURCE_ANDROID,context.SOURCE_LINUX,context.SOURCE_CERTIFI,context.PLATFORM_ANDROID12,context.PLATFORM_ANDROID11,context.PLATFORM_ANDROID10,context.PLATFORM_ANDROID9,context.PLATFORM_ANDROID8,context.PLATFORM_ANDROID7}

    def exists(self, context_type :int) -> bool:
        if not TrustStore.valid_context_type(context_type):
            raise AttributeError(context.INVALID_CONTEXT)
        if context_type == context.SOURCE_APPLE and datetime.utcnow() >= datetime(2021, 12, 1):
            context_type = context.SOURCE_CCADB
            logger.warning(DeprecationWarning(DEPRECATION_MESSAGE), exc_info=True)

        if context_type == context.SOURCE_CCADB and self.ca_common_name in CCADB_PEM_FILES.keys():
            return self.match_certificate(self.get_certificate_from_store(context.SOURCE_CCADB))
        if context_type == context.SOURCE_JAVA and self.ca_common_name in JAVA_PEM_FILES.keys():
            return self.match_certificate(self.get_certificate_from_store(context.SOURCE_JAVA))
        if context_type == context.SOURCE_ANDROID and self.ca_common_name in ANDROID_PEM_FILES.keys():
            return self.match_certificate(self.get_certificate_from_store(context.SOURCE_ANDROID))
        if context_type == context.SOURCE_LINUX and self.ca_common_name in LINUX_PEM_FILES.keys():
            return self.match_certificate(self.get_certificate_from_store(context.SOURCE_LINUX))
        if context_type == context.SOURCE_CERTIFI and self.ca_common_name in CERTIFI_PEM_FILES.keys():
            return self.match_certificate(self.get_certificate_from_store(context.SOURCE_CERTIFI))
        if context_type == context.SOURCE_APPLE:
            logger.warning(DeprecationWarning(DEPRECATION_MESSAGE), exc_info=True)
            for data in REFERENCE_DATA:
                if self.ca_common_name == data.get(APPLE_KEY_CA_CN):
                    return True
        if context_type == context.PLATFORM_ANDROID12 and self.ca_common_name in ANDROID12_PEM_FILES.keys():
            return self.match_certificate(self.get_certificate_from_store(context.PLATFORM_ANDROID12))
        if context_type == context.PLATFORM_ANDROID11 and self.ca_common_name in ANDROID11_PEM_FILES.keys():
            return self.match_certificate(self.get_certificate_from_store(context.PLATFORM_ANDROID11))
        if context_type == context.PLATFORM_ANDROID10 and self.ca_common_name in ANDROID10_PEM_FILES.keys():
            return self.match_certificate(self.get_certificate_from_store(context.PLATFORM_ANDROID10))
        if context_type == context.PLATFORM_ANDROID9 and self.ca_common_name in ANDROID9_PEM_FILES.keys():
            return self.match_certificate(self.get_certificate_from_store(context.PLATFORM_ANDROID9))
        if context_type == context.PLATFORM_ANDROID8 and self.ca_common_name in ANDROID8_PEM_FILES.keys():
            return self.match_certificate(self.get_certificate_from_store(context.PLATFORM_ANDROID8))
        if context_type == context.PLATFORM_ANDROID7 and self.ca_common_name in ANDROID7_PEM_FILES.keys():
            return self.match_certificate(self.get_certificate_from_store(context.PLATFORM_ANDROID7))
        return False

    def expired_in_store(self, context_type :int) -> bool:
        if not TrustStore.valid_context_type(context_type):
            raise AttributeError(context.INVALID_CONTEXT)
        if context_type == context.SOURCE_APPLE and datetime.utcnow() >= datetime(2021, 12, 1):
            context_type = context.SOURCE_CCADB
            logger.warning(DeprecationWarning(DEPRECATION_MESSAGE), exc_info=True)
        if not self.exists(context_type=context_type):
            raise FileExistsError('Certificate does not exist')
        if context_type == context.SOURCE_APPLE:
            logger.warning(DeprecationWarning(DEPRECATION_MESSAGE), exc_info=True)
            for data in REFERENCE_DATA:
                if self.ca_common_name == data.get(APPLE_KEY_CA_CN):
                    return datetime.utcnow() > datetime.strptime(data.get(APPLE_KEY_EXPIRES), APPLE_DATE_FMT)
        return self.get_certificate_from_store(context_type=context_type).has_expired()

    def get_certificate_from_store(self, context_type :int) -> X509:
        if not TrustStore.valid_context_type(context_type):
            raise AttributeError(context.INVALID_CONTEXT)
        if context_type == context.SOURCE_APPLE and datetime.utcnow() >= datetime(2021, 12, 1):
            context_type = context.SOURCE_CCADB
            logger.warning(DeprecationWarning(DEPRECATION_MESSAGE), exc_info=True)

        if context_type == context.SOURCE_APPLE:
            raise NotImplementedError('Legacy Apple does not support this method and will end April 1, 2022')
        certificate = None
        try:
            if context_type == context.SOURCE_CCADB:
                certificate = load_certificate(FILETYPE_PEM, CCADB_PEM_FILES[self.ca_common_name].encode())
            if context_type == context.SOURCE_ANDROID:
                certificate = load_certificate(FILETYPE_PEM, ANDROID_PEM_FILES[self.ca_common_name].encode())
            if context_type == context.SOURCE_JAVA:
                certificate = load_certificate(FILETYPE_PEM, JAVA_PEM_FILES[self.ca_common_name].encode())
            if context_type == context.SOURCE_LINUX:
                certificate = load_certificate(FILETYPE_PEM, LINUX_PEM_FILES[self.ca_common_name].encode())
            if context_type == context.SOURCE_CERTIFI:
                certificate = load_certificate(FILETYPE_PEM, CERTIFI_PEM_FILES[self.ca_common_name].encode())
            if context_type == context.PLATFORM_ANDROID7:
                certificate = load_certificate(FILETYPE_PEM, ANDROID7_PEM_FILES[self.ca_common_name].encode())
            if context_type == context.PLATFORM_ANDROID8:
                certificate = load_certificate(FILETYPE_PEM, ANDROID8_PEM_FILES[self.ca_common_name].encode())
            if context_type == context.PLATFORM_ANDROID9:
                certificate = load_certificate(FILETYPE_PEM, ANDROID9_PEM_FILES[self.ca_common_name].encode())
            if context_type == context.PLATFORM_ANDROID10:
                certificate = load_certificate(FILETYPE_PEM, ANDROID10_PEM_FILES[self.ca_common_name].encode())
            if context_type == context.PLATFORM_ANDROID11:
                certificate = load_certificate(FILETYPE_PEM, ANDROID11_PEM_FILES[self.ca_common_name].encode())
            if context_type == context.PLATFORM_ANDROID12:
                certificate = load_certificate(FILETYPE_PEM, ANDROID12_PEM_FILES[self.ca_common_name].encode())
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

        if context_type == context.SOURCE_APPLE and datetime.utcnow() >= datetime(2021, 12, 1):
            context_type = context.SOURCE_CCADB
            logger.warning(DeprecationWarning(DEPRECATION_MESSAGE), exc_info=True)

        if context_type == context.SOURCE_CCADB:
            return self.ccadb
        if context_type == context.SOURCE_JAVA:
            return self.java
        if context_type == context.SOURCE_APPLE:
            logger.warning(DeprecationWarning(DEPRECATION_MESSAGE), exc_info=True)
            return self.apple
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
        if context_type == context.SOURCE_LINUX:
            return self.linux
        if context_type == context.SOURCE_CERTIFI:
            return self.certifi

        return self.is_trusted
