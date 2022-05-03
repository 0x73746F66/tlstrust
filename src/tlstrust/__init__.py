import sys
import logging
from datetime import datetime
from OpenSSL.crypto import X509
from .util import (
    InvalidChainError,
    get_cn_or_org,
    valid_context_type,
    get_certificate_from_store,
    match_certificate,
    get_leaf,
    build_chains,
    get_store_result_text,
)
from .context import *  # noqa: F403
from .stores.android_2_2 import (
    UNTRUSTED as ANDROID2_2_UNTRUSTED,
    PEM_FILES as ANDROID2_2_PEM_FILES,
)
from .stores.android_2_3 import (
    UNTRUSTED as ANDROID2_3_UNTRUSTED,
    PEM_FILES as ANDROID2_3_PEM_FILES,
)
from .stores.android_3 import (
    UNTRUSTED as ANDROID3_UNTRUSTED,
    PEM_FILES as ANDROID3_PEM_FILES,
)
from .stores.android_4_4 import (
    UNTRUSTED as ANDROID4_4_UNTRUSTED,
    PEM_FILES as ANDROID4_4_PEM_FILES,
)
from .stores.android_4 import (
    UNTRUSTED as ANDROID4_UNTRUSTED,
    PEM_FILES as ANDROID4_PEM_FILES,
)
from .stores.android_7 import (
    UNTRUSTED as ANDROID7_UNTRUSTED,
    PEM_FILES as ANDROID7_PEM_FILES,
)
from .stores.android_8 import (
    UNTRUSTED as ANDROID8_UNTRUSTED,
    PEM_FILES as ANDROID8_PEM_FILES,
)
from .stores.android_9 import (
    UNTRUSTED as ANDROID9_UNTRUSTED,
    PEM_FILES as ANDROID9_PEM_FILES,
)
from .stores.android_10 import (
    UNTRUSTED as ANDROID10_UNTRUSTED,
    PEM_FILES as ANDROID10_PEM_FILES,
)
from .stores.android_11 import (
    UNTRUSTED as ANDROID11_UNTRUSTED,
    PEM_FILES as ANDROID11_PEM_FILES,
)
from .stores.android_12 import (
    UNTRUSTED as ANDROID12_UNTRUSTED,
    PEM_FILES as ANDROID12_PEM_FILES,
)
from .stores.android_13 import (
    UNTRUSTED as ANDROID13_UNTRUSTED,
    PEM_FILES as ANDROID13_PEM_FILES,
)
from .stores.android_14 import (
    UNTRUSTED as ANDROID14_UNTRUSTED,
    PEM_FILES as ANDROID14_PEM_FILES,
)
from .stores.android_latest import (
    UNTRUSTED as ANDROID_UNTRUSTED,
    PEM_FILES as ANDROID_PEM_FILES,
)
from .stores.ccadb import UNTRUSTED as CCADB_UNTRUSTED, PEM_FILES as CCADB_PEM_FILES
from .stores.java import UNTRUSTED as JAVA_UNTRUSTED, PEM_FILES as JAVA_PEM_FILES
from .stores.certifi import (
    UNTRUSTED as CERTIFI_UNTRUSTED,
    PEM_FILES as CERTIFI_PEM_FILES,
)
from .stores.mintsifry_rossii import (
    UNTRUSTED as RUSSIA_UNTRUSTED,
    PEM_FILES as RUSSIA_PEM_FILES,
)
from .stores.rustls import (
    UNTRUSTED as RUST_UNTRUSTED,
    PEM_FILES as RUST_PEM_FILES,
)
from .stores.curl import (
    UNTRUSTED as CURL_UNTRUSTED,
    PEM_FILES as CURL_PEM_FILES,
)
from .stores.dart import (
    UNTRUSTED as DART_UNTRUSTED,
    PEM_FILES as DART_PEM_FILES,
)

__module__ = "tlstrust"
__version__ = "2.6.1"

assert sys.version_info >= (3, 9), "Requires Python 3.9 or newer"

logger = logging.getLogger(__name__)


class TrustStore:
    key_identifier: str

    def __init__(self, authority_key_identifier: str) -> bool:
        if not isinstance(authority_key_identifier, str):
            raise TypeError(
                f"authority_key_identifier type {type(authority_key_identifier)} not supported, expected str"
            )
        # used for Root CA matching, SKI is authoritative
        self.key_identifier = authority_key_identifier
        for _, ctx in SOURCES.items():
            if self.exists(context_type=ctx):
                break

    def to_dict(self) -> dict:
        subject_common_name = get_cn_or_org(self.certificate)
        data = {
            "trust_stores": [],
            "_metadata": {
                "last_updated": datetime.utcnow().replace(microsecond=0).isoformat(),
                "certificate_not_valid_after": self.certificate.to_cryptography().not_valid_after,
                "certificate_issuer": subject_common_name,
                "certificate_issuer_ski": self.key_identifier,
            },
        }
        for name, ctx in ALL_DISTINCT.items():
            result = {}
            result["short_name"] = SHORT_LOOKUP.get(name, name)
            result["name"] = name
            result["is_trusted"] = self.check_trust(ctx)
            try:
                result["exists"] = isinstance(self.certificate, X509)
                result["expired"] = self.expired_in_store(ctx)
            except FileExistsError:
                result["exists"] = False
            result["description"] = get_store_result_text(**result)
            data["trust_stores"].append(result)
        return data

    @property
    def all_results(self) -> dict:
        results = {}
        for name, ctx in ALL_DISTINCT.items():
            try:
                results[name] = self.check_trust(ctx)
            except FileExistsError:
                results[name] = False
        return results

    @property
    def certificate(self) -> X509:
        certificate = None
        for _, context_type in STORES.items():
            try:
                certificate = get_certificate_from_store(
                    self.key_identifier, context_type
                )
            except FileExistsError:
                continue
            if isinstance(certificate, X509):
                break
        return certificate

    @property
    def ccadb(self) -> bool:
        try:
            return (
                self.key_identifier not in CCADB_UNTRUSTED
                and isinstance(self.certificate, X509)
                and not self.expired_in_store(SOURCE_CCADB)
            )
        except FileExistsError:
            return False

    @property
    def java(self) -> bool:
        try:
            return (
                self.key_identifier not in JAVA_UNTRUSTED
                and isinstance(self.certificate, X509)
                and not self.expired_in_store(SOURCE_JAVA)
            )
        except FileExistsError:
            return False

    @property
    def android(self) -> bool:
        untrusted = set(
            ANDROID_UNTRUSTED
            + ANDROID2_2_UNTRUSTED
            + ANDROID2_3_UNTRUSTED
            + ANDROID3_UNTRUSTED
            + ANDROID4_UNTRUSTED
            + ANDROID4_4_UNTRUSTED
            + ANDROID7_UNTRUSTED
            + ANDROID8_UNTRUSTED
            + ANDROID9_UNTRUSTED
            + ANDROID10_UNTRUSTED
            + ANDROID11_UNTRUSTED
            + ANDROID12_UNTRUSTED
            + ANDROID13_UNTRUSTED
            + ANDROID14_UNTRUSTED
        )
        try:
            return (
                self.key_identifier not in untrusted
                and isinstance(self.certificate, X509)
                and not self.expired_in_store(SOURCE_ANDROID)
            )
        except FileExistsError:
            return False

    @property
    def android_latest(self) -> bool:
        try:
            return (
                self.key_identifier not in ANDROID_UNTRUSTED
                and isinstance(self.certificate, X509)
                and not self.expired_in_store(PLATFORM_ANDROID_LATEST)
            )
        except FileExistsError:
            return False

    @property
    def android14(self) -> bool:
        try:
            return (
                self.key_identifier not in ANDROID14_UNTRUSTED
                and isinstance(self.certificate, X509)
                and not self.expired_in_store(PLATFORM_ANDROID14)
            )
        except FileExistsError:
            return False

    @property
    def android13(self) -> bool:
        try:
            return (
                self.key_identifier not in ANDROID13_UNTRUSTED
                and isinstance(self.certificate, X509)
                and not self.expired_in_store(PLATFORM_ANDROID13)
            )
        except FileExistsError:
            return False

    @property
    def android12(self) -> bool:
        try:
            return (
                self.key_identifier not in ANDROID12_UNTRUSTED
                and isinstance(self.certificate, X509)
                and not self.expired_in_store(PLATFORM_ANDROID12)
            )
        except FileExistsError:
            return False

    @property
    def android11(self) -> bool:
        try:
            return (
                self.key_identifier not in ANDROID11_UNTRUSTED
                and isinstance(self.certificate, X509)
                and not self.expired_in_store(PLATFORM_ANDROID11)
            )
        except FileExistsError:
            return False

    @property
    def android10(self) -> bool:
        try:
            return (
                self.key_identifier not in ANDROID10_UNTRUSTED
                and isinstance(self.certificate, X509)
                and not self.expired_in_store(PLATFORM_ANDROID10)
            )
        except FileExistsError:
            return False

    @property
    def android9(self) -> bool:
        try:
            return (
                self.key_identifier not in ANDROID9_UNTRUSTED
                and isinstance(self.certificate, X509)
                and not self.expired_in_store(PLATFORM_ANDROID9)
            )
        except FileExistsError:
            return False

    @property
    def android8(self) -> bool:
        try:
            return (
                self.key_identifier not in ANDROID8_UNTRUSTED
                and isinstance(self.certificate, X509)
                and not self.expired_in_store(PLATFORM_ANDROID8)
            )
        except FileExistsError:
            return False

    @property
    def android7(self) -> bool:
        try:
            return (
                self.key_identifier not in ANDROID7_UNTRUSTED
                and isinstance(self.certificate, X509)
                and not self.expired_in_store(PLATFORM_ANDROID7)
            )
        except FileExistsError:
            return False

    @property
    def android4_4(self) -> bool:
        try:
            return (
                self.key_identifier not in ANDROID4_4_UNTRUSTED
                and isinstance(self.certificate, X509)
                and not self.expired_in_store(PLATFORM_ANDROID4_4)
            )
        except FileExistsError:
            return False

    @property
    def android4(self) -> bool:
        try:
            return (
                self.key_identifier not in ANDROID4_UNTRUSTED
                and isinstance(self.certificate, X509)
                and not self.expired_in_store(PLATFORM_ANDROID4)
            )
        except FileExistsError:
            return False

    @property
    def android3(self) -> bool:
        try:
            return (
                self.key_identifier not in ANDROID3_UNTRUSTED
                and isinstance(self.certificate, X509)
                and not self.expired_in_store(PLATFORM_ANDROID3)
            )
        except FileExistsError:
            return False

    @property
    def android2_3(self) -> bool:
        try:
            return (
                self.key_identifier not in ANDROID2_3_UNTRUSTED
                and isinstance(self.certificate, X509)
                and not self.expired_in_store(PLATFORM_ANDROID2_3)
            )
        except FileExistsError:
            return False

    @property
    def android2_2(self) -> bool:
        try:
            return (
                self.key_identifier not in ANDROID2_2_UNTRUSTED
                and isinstance(self.certificate, X509)
                and not self.expired_in_store(PLATFORM_ANDROID2_2)
            )
        except FileExistsError:
            return False

    @property
    def certifi(self) -> bool:
        try:
            return (
                self.key_identifier not in CERTIFI_UNTRUSTED
                and isinstance(self.certificate, X509)
                and not self.expired_in_store(SOURCE_CERTIFI)
            )
        except FileExistsError:
            return False

    @property
    def russia(self) -> bool:
        try:
            return (
                self.key_identifier not in RUSSIA_UNTRUSTED
                and isinstance(self.certificate, X509)
                and not self.expired_in_store(SOURCE_RUSSIA)
            )
        except FileExistsError:
            return False

    @property
    def rustls(self) -> bool:
        try:
            return (
                self.key_identifier not in RUST_UNTRUSTED
                and isinstance(self.certificate, X509)
                and not self.expired_in_store(SOURCE_RUSTLS)
            )
        except FileExistsError:
            return False

    @property
    def curl(self) -> bool:
        try:
            return (
                self.key_identifier not in CURL_UNTRUSTED
                and isinstance(self.certificate, X509)
                and not self.expired_in_store(SOURCE_CURL)
            )
        except FileExistsError:
            return False

    @property
    def dart(self) -> bool:
        try:
            return (
                self.key_identifier not in DART_UNTRUSTED
                and isinstance(self.certificate, X509)
                and not self.expired_in_store(SOURCE_DART)
            )
        except FileExistsError:
            return False

    @property
    def is_trusted(self) -> bool:
        return all(
            [
                self.ccadb,
                self.android,
                self.curl,
                self.dart,
                self.certifi,
                self.java,
                self.russia,
                self.rustls,
            ]
        )

    def exists(self, context_type: int) -> bool:
        if not valid_context_type(context_type):
            raise AttributeError(INVALID_CONTEXT.format(context_type))

        if (
            context_type == SOURCE_CCADB
            and self.key_identifier in CCADB_PEM_FILES.keys()
        ):
            return match_certificate(
                self.key_identifier,
                get_certificate_from_store(self.key_identifier, SOURCE_CCADB),
            )
        if context_type == SOURCE_JAVA and self.key_identifier in JAVA_PEM_FILES.keys():
            return match_certificate(
                self.key_identifier,
                get_certificate_from_store(self.key_identifier, SOURCE_JAVA),
            )
        if (
            context_type == SOURCE_ANDROID
            and self.key_identifier in ANDROID_PEM_FILES.keys()
        ):
            return match_certificate(
                self.key_identifier,
                get_certificate_from_store(self.key_identifier, SOURCE_ANDROID),
            )
        if (
            context_type == SOURCE_RUSSIA
            and self.key_identifier in RUSSIA_PEM_FILES.keys()
        ):
            return match_certificate(
                self.key_identifier,
                get_certificate_from_store(self.key_identifier, SOURCE_RUSSIA),
            )
        if (
            context_type == SOURCE_RUSTLS
            and self.key_identifier in RUST_PEM_FILES.keys()
        ):
            return match_certificate(
                self.key_identifier,
                get_certificate_from_store(self.key_identifier, SOURCE_RUSTLS),
            )
        if context_type == SOURCE_CURL and self.key_identifier in CURL_PEM_FILES.keys():
            return match_certificate(
                self.key_identifier,
                get_certificate_from_store(self.key_identifier, SOURCE_CURL),
            )
        if context_type == SOURCE_DART and self.key_identifier in DART_PEM_FILES.keys():
            return match_certificate(
                self.key_identifier,
                get_certificate_from_store(self.key_identifier, SOURCE_DART),
            )
        if (
            context_type == SOURCE_CERTIFI
            and self.key_identifier in CERTIFI_PEM_FILES.keys()
        ):
            return match_certificate(
                self.key_identifier,
                get_certificate_from_store(self.key_identifier, SOURCE_CERTIFI),
            )
        if (
            context_type == PLATFORM_ANDROID14
            and self.key_identifier in ANDROID14_PEM_FILES.keys()
        ):
            return match_certificate(
                self.key_identifier,
                get_certificate_from_store(self.key_identifier, PLATFORM_ANDROID14),
            )
        if (
            context_type == PLATFORM_ANDROID13
            and self.key_identifier in ANDROID13_PEM_FILES.keys()
        ):
            return match_certificate(
                self.key_identifier,
                get_certificate_from_store(self.key_identifier, PLATFORM_ANDROID13),
            )
        if (
            context_type == PLATFORM_ANDROID12
            and self.key_identifier in ANDROID12_PEM_FILES.keys()
        ):
            return match_certificate(
                self.key_identifier,
                get_certificate_from_store(self.key_identifier, PLATFORM_ANDROID12),
            )
        if (
            context_type == PLATFORM_ANDROID11
            and self.key_identifier in ANDROID11_PEM_FILES.keys()
        ):
            return match_certificate(
                self.key_identifier,
                get_certificate_from_store(self.key_identifier, PLATFORM_ANDROID11),
            )
        if (
            context_type == PLATFORM_ANDROID10
            and self.key_identifier in ANDROID10_PEM_FILES.keys()
        ):
            return match_certificate(
                self.key_identifier,
                get_certificate_from_store(self.key_identifier, PLATFORM_ANDROID10),
            )
        if (
            context_type == PLATFORM_ANDROID9
            and self.key_identifier in ANDROID9_PEM_FILES.keys()
        ):
            return match_certificate(
                self.key_identifier,
                get_certificate_from_store(self.key_identifier, PLATFORM_ANDROID9),
            )
        if (
            context_type == PLATFORM_ANDROID8
            and self.key_identifier in ANDROID8_PEM_FILES.keys()
        ):
            return match_certificate(
                self.key_identifier,
                get_certificate_from_store(self.key_identifier, PLATFORM_ANDROID8),
            )
        if (
            context_type == PLATFORM_ANDROID7
            and self.key_identifier in ANDROID7_PEM_FILES.keys()
        ):
            return match_certificate(
                self.key_identifier,
                get_certificate_from_store(self.key_identifier, PLATFORM_ANDROID7),
            )
        if (
            context_type == PLATFORM_ANDROID4_4
            and self.key_identifier in ANDROID4_4_PEM_FILES.keys()
        ):
            return match_certificate(
                self.key_identifier,
                get_certificate_from_store(self.key_identifier, PLATFORM_ANDROID7),
            )
        if (
            context_type == PLATFORM_ANDROID4
            and self.key_identifier in ANDROID4_PEM_FILES.keys()
        ):
            return match_certificate(
                self.key_identifier,
                get_certificate_from_store(self.key_identifier, PLATFORM_ANDROID7),
            )
        if (
            context_type == PLATFORM_ANDROID3
            and self.key_identifier in ANDROID3_PEM_FILES.keys()
        ):
            return match_certificate(
                self.key_identifier,
                get_certificate_from_store(self.key_identifier, PLATFORM_ANDROID7),
            )
        if (
            context_type == PLATFORM_ANDROID2_3
            and self.key_identifier in ANDROID2_3_PEM_FILES.keys()
        ):
            return match_certificate(
                self.key_identifier,
                get_certificate_from_store(self.key_identifier, PLATFORM_ANDROID7),
            )
        if (
            context_type == PLATFORM_ANDROID2_2
            and self.key_identifier in ANDROID2_2_PEM_FILES.keys()
        ):
            return match_certificate(
                self.key_identifier,
                get_certificate_from_store(self.key_identifier, PLATFORM_ANDROID7),
            )
        return False

    def expired_in_store(self, context_type: int) -> bool:
        if not valid_context_type(context_type):
            raise AttributeError(INVALID_CONTEXT.format(context_type))
        if not self.exists(context_type=context_type):
            raise FileExistsError("Certificate does not exist")
        return get_certificate_from_store(
            self.key_identifier, context_type=context_type
        ).has_expired()

    def check_trust(self, context_type: int = None) -> bool:
        if context_type is not None and not isinstance(context_type, int):
            raise TypeError(
                f"context type {type(context_type)} not supported, expected int"
            )
        if not valid_context_type(context_type):
            raise AttributeError(INVALID_CONTEXT.format(context_type))

        if context_type == SOURCE_CCADB:
            return self.ccadb
        if context_type == SOURCE_JAVA:
            return self.java
        if context_type == SOURCE_ANDROID:
            return self.android
        if context_type == PLATFORM_ANDROID14:
            return self.android14
        if context_type == PLATFORM_ANDROID13:
            return self.android13
        if context_type == PLATFORM_ANDROID12:
            return self.android12
        if context_type == PLATFORM_ANDROID11:
            return self.android11
        if context_type == PLATFORM_ANDROID10:
            return self.android10
        if context_type == PLATFORM_ANDROID9:
            return self.android9
        if context_type == PLATFORM_ANDROID8:
            return self.android8
        if context_type == PLATFORM_ANDROID7:
            return self.android7
        if context_type == PLATFORM_ANDROID4_4:
            return self.android4_4
        if context_type == PLATFORM_ANDROID4:
            return self.android4
        if context_type == PLATFORM_ANDROID3:
            return self.android3
        if context_type == PLATFORM_ANDROID2_3:
            return self.android2_3
        if context_type == PLATFORM_ANDROID2_2:
            return self.android2_2
        if context_type == SOURCE_CERTIFI:
            return self.certifi
        if context_type == SOURCE_RUSSIA:
            return self.russia
        if context_type == SOURCE_RUSTLS:
            return self.rustls
        if context_type == SOURCE_CURL:
            return self.curl
        if context_type == SOURCE_DART:
            return self.dart

        return self.is_trusted


def trust_stores_from_chain(certificates: list[X509]) -> list[TrustStore]:
    leaf = get_leaf(certificates)
    if not isinstance(leaf, X509):
        raise InvalidChainError(
            "certificate chain is empty or missing a server leaf certificate"
        )
    chain = build_chains(leaf, certificates)
    return [TrustStore(root.get("ski")) for _, root in chain.items()]
