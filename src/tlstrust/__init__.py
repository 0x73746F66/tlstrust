import logging
from datetime import datetime
from OpenSSL.crypto import FILETYPE_ASN1, X509, FILETYPE_PEM, load_certificate
from tlstrust import context
from tlstrust.stores.apple import UNTRUSTED as APPLE_UNTRUSTED, REFERENCE_DATA
from tlstrust.stores.android import UNTRUSTED as ANDROID_UNTRUSTED, PEM_FILES as ANDROID_PEM_FILES
from tlstrust.stores.ccadb import UNTRUSTED as CCADB_UNTRUSTED, PEM_FILES as CCADB_PEM_FILES
from tlstrust.stores.java import UNTRUSTED as JAVA_UNTRUSTED, PEM_FILES as JAVA_PEM_FILES
from tlstrust.stores.linux import UNTRUSTED as LINUX_UNTRUSTED, PEM_FILES as LINUX_PEM_FILES
from tlstrust.stores.certifi import UNTRUSTED as CERTIFI_UNTRUSTED, PEM_FILES as CERTIFI_PEM_FILES

__module__ = 'tlstrust'
logger = logging.getLogger(__name__)
DEPRECATION_MESSAGE = 'Apple legacy supports will be removed April 1, 2022'
APPLE_DATE_FMT = '%H:%M:%S %d %b %Y'
APPLE_KEY_CA_CN = 'Certificate name'
APPLE_KEY_EXPIRES = 'Expires'
UNTRUSTED = list(set(APPLE_UNTRUSTED + ANDROID_UNTRUSTED + CCADB_UNTRUSTED + JAVA_UNTRUSTED + LINUX_UNTRUSTED + CERTIFI_UNTRUSTED))

class TrustStore:
    _certificate :X509
    ca_common_name :str

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
        self.ca_common_name = None
        if isinstance(ca_common_name, str):
            self.ca_common_name = ca_common_name
        if hasattr(self, '_certificate') and isinstance(self._certificate, X509):
            self.ca_common_name = self._certificate.get_issuer().commonName
        if isinstance(ca_common_name, str):
            self.ca_common_name = ca_common_name
            for ctx in [context.SOURCE_CCADB, context.SOURCE_CERTIFI, context.SOURCE_ANDROID, context.SOURCE_APPLE, context.SOURCE_JAVA, context.SOURCE_LINUX]:
                if self.exists(context_type=ctx):
                    self._certificate = self.get_certificate_from_store(context_type=ctx)
                    break

    @property
    def ccadb(self) -> bool:
        return self.ca_common_name not in UNTRUSTED and self.ca_common_name in CCADB_PEM_FILES.keys()

    @property
    def apple(self) -> bool:
        logger.warning(DeprecationWarning(DEPRECATION_MESSAGE), exc_info=True)
        return self.ca_common_name not in UNTRUSTED and self.ca_common_name in [data.get(APPLE_KEY_CA_CN).strip() for data in REFERENCE_DATA if self.ca_common_name == data.get(APPLE_KEY_CA_CN).strip() and datetime.utcnow() < datetime.strptime(data.get(APPLE_KEY_EXPIRES), APPLE_DATE_FMT)]

    @property
    def java(self) -> bool:
        return self.ca_common_name not in UNTRUSTED and self.ca_common_name in JAVA_PEM_FILES.keys()

    @property
    def android(self) -> bool:
        return self.ca_common_name not in UNTRUSTED and self.ca_common_name in ANDROID_PEM_FILES.keys()

    @property
    def linux(self) -> bool:
        return self.ca_common_name not in UNTRUSTED and self.ca_common_name in LINUX_PEM_FILES.keys()

    @property
    def certifi(self) -> bool:
        return self.ca_common_name not in UNTRUSTED and self.ca_common_name in CERTIFI_PEM_FILES.keys()

    @property
    def is_trusted(self) -> bool:
        apple_legacy = datetime.utcnow() < datetime(2021, 12, 1)
        evaluations = [self.ccadb, self.android, self.linux, self.certifi, self.java]
        if apple_legacy: evaluations.append(self.apple)
        return all(evaluations)

    @staticmethod
    def valid_context_type(context_type :int) -> bool:
        return context_type in {None,context.SOURCE_CCADB,context.SOURCE_JAVA,context.SOURCE_APPLE,context.SOURCE_ANDROID,context.SOURCE_LINUX,context.SOURCE_CERTIFI}

    def exists(self, context_type :int) -> bool:
        if not TrustStore.valid_context_type(context_type):
            raise AttributeError(context.INVALID_CONTEXT)
        if context_type == context.SOURCE_APPLE and datetime.utcnow() >= datetime(2021, 12, 1):
            context_type = context.SOURCE_CCADB
            logger.warning(DeprecationWarning(DEPRECATION_MESSAGE), exc_info=True)

        if context_type == context.SOURCE_CCADB:
            return self.ca_common_name in CCADB_PEM_FILES.keys()
        if context_type == context.SOURCE_JAVA:
            return self.ca_common_name in JAVA_PEM_FILES.keys()
        if context_type == context.SOURCE_APPLE:
            logger.warning(DeprecationWarning(DEPRECATION_MESSAGE), exc_info=True)
            for data in REFERENCE_DATA:
                if self.ca_common_name == data.get(APPLE_KEY_CA_CN):
                    return True
        if context_type == context.SOURCE_ANDROID:
            return self.ca_common_name in ANDROID_PEM_FILES.keys()
        if context_type == context.SOURCE_LINUX:
            return self.ca_common_name in LINUX_PEM_FILES.keys()
        if context_type == context.SOURCE_CERTIFI:
            return self.ca_common_name in CERTIFI_PEM_FILES.keys()
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
        if not self.exists(context_type=context_type):
            raise FileExistsError('Certificate does not exist')
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
        if context_type == context.SOURCE_LINUX:
            return self.linux
        if context_type == context.SOURCE_CERTIFI:
            return self.certifi

        return self.is_trusted
