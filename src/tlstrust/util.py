import ssl
from socket import socket, AF_INET, SOCK_STREAM
from binascii import hexlify
import idna
import validators
from certifi import where
from OpenSSL import SSL
from OpenSSL.crypto import X509, FILETYPE_PEM, load_certificate
from cryptography import x509
from cryptography.x509.base import Certificate
from cryptography.x509.extensions import (
    Extension,
    SubjectKeyIdentifier,
    AuthorityKeyIdentifier,
)
from .context import *  # noqa: F403
from .stores import VERSIONS
from .stores.android_2_2 import PEM_FILES as ANDROID2_2_PEM_FILES
from .stores.android_2_3 import PEM_FILES as ANDROID2_3_PEM_FILES
from .stores.android_3 import PEM_FILES as ANDROID3_PEM_FILES
from .stores.android_4_4 import PEM_FILES as ANDROID4_4_PEM_FILES
from .stores.android_4 import PEM_FILES as ANDROID4_PEM_FILES
from .stores.android_7 import PEM_FILES as ANDROID7_PEM_FILES
from .stores.android_8 import PEM_FILES as ANDROID8_PEM_FILES
from .stores.android_9 import PEM_FILES as ANDROID9_PEM_FILES
from .stores.android_10 import PEM_FILES as ANDROID10_PEM_FILES
from .stores.android_11 import PEM_FILES as ANDROID11_PEM_FILES
from .stores.android_12 import PEM_FILES as ANDROID12_PEM_FILES
from .stores.android_13 import PEM_FILES as ANDROID13_PEM_FILES
from .stores.android_14 import PEM_FILES as ANDROID14_PEM_FILES
from .stores.android_latest import PEM_FILES as ANDROID_PEM_FILES
from .stores.ccadb import PEM_FILES as CCADB_PEM_FILES
from .stores.java import PEM_FILES as JAVA_PEM_FILES
from .stores.certifi import PEM_FILES as CERTIFI_PEM_FILES
from .stores.mintsifry_rossii import PEM_FILES as RUSSIA_PEM_FILES
from .stores.rustls import PEM_FILES as RUST_PEM_FILES
from .stores.curl import PEM_FILES as CURL_PEM_FILES
from .stores.dart import PEM_FILES as DART_PEM_FILES

__module__ = "tlstrust.util"

MISSING_MESSAGE = "Certificate does not exist"


class InvalidChainError(ValueError):
    """Raised when the certificate chain is empty or missing a server leaf certificate"""


def valid_context_type(context_type: int) -> bool:
    return context_type is None or context_type in [ctx for _, ctx in STORES.items()]


def get_key_identifier_hex(cert: Certificate, extension: Extension, key: str) -> str:
    for ext in cert.extensions:
        if isinstance(ext.value, extension):
            return hexlify(getattr(ext.value, key)).decode("utf-8")


def match_certificate(aki, root_ca: X509) -> bool:
    return any(
        isinstance(ext.value, SubjectKeyIdentifier)
        and aki == hexlify(ext.value.key_identifier).decode("utf-8")
        for ext in root_ca.to_cryptography().extensions
    )


def get_certificate_chain(
    host: str, port: int, use_sni: bool = True, client_cert: X509 = None
) -> tuple[list[X509], str]:
    if not isinstance(port, int):
        raise TypeError(f"provided an invalid type {type(port)} for port, expected int")
    if validators.domain(host) is not True:
        raise ValueError(f"provided an invalid domain {host}")

    for method in [
        "TLSv1_METHOD",
        "TLSv1_1_METHOD",
        "TLSv1_2_METHOD",
        "SSLv23_METHOD",
    ]:
        ctx = SSL.Context(method=getattr(SSL, method))
        ctx.load_verify_locations(cafile=where())
        if isinstance(client_cert, X509):
            ctx.use_certificate(client_cert)
        ctx.verify_mode = SSL.VERIFY_NONE
        ctx.check_hostname = False
        sock = socket(AF_INET, SOCK_STREAM)
        sock.settimeout(2)
        conn = SSL.Connection(ctx, sock)
        if all([ssl.HAS_SNI, use_sni]):
            conn.set_tlsext_host_name(idna.encode(host))
        certificate_chain = []
        skip = False
        try:
            conn.connect((host, port))
            conn.set_connect_state()
            conn.setblocking(1)
            conn.do_handshake()
            peer_address, _ = conn.getpeername()
            for (_, cert) in enumerate(conn.get_peer_cert_chain()):
                certificate_chain.append(cert)
            conn.shutdown()
        except SSL.Error:
            skip = True
        finally:
            conn.close()
        if skip:
            continue
        return certificate_chain, peer_address


def get_certificate_from_store(aki, context_type: int) -> X509:
    if not valid_context_type(context_type):
        raise AttributeError(INVALID_CONTEXT.format(context_type))
    certificate = None
    try:
        if context_type == SOURCE_CCADB:
            certificate = load_certificate(FILETYPE_PEM, CCADB_PEM_FILES[aki].encode())
        if context_type == SOURCE_ANDROID:
            certificate = load_certificate(
                FILETYPE_PEM, ANDROID_PEM_FILES[aki].encode()
            )
        if context_type == SOURCE_JAVA:
            certificate = load_certificate(FILETYPE_PEM, JAVA_PEM_FILES[aki].encode())
        if context_type == SOURCE_RUSSIA:
            certificate = load_certificate(FILETYPE_PEM, RUSSIA_PEM_FILES[aki].encode())
        if context_type == SOURCE_RUSTLS:
            certificate = load_certificate(FILETYPE_PEM, RUST_PEM_FILES[aki].encode())
        if context_type == SOURCE_CURL:
            certificate = load_certificate(FILETYPE_PEM, CURL_PEM_FILES[aki].encode())
        if context_type == SOURCE_DART:
            certificate = load_certificate(FILETYPE_PEM, DART_PEM_FILES[aki].encode())
        if context_type == SOURCE_CERTIFI:
            certificate = load_certificate(
                FILETYPE_PEM, CERTIFI_PEM_FILES[aki].encode()
            )
        if context_type == PLATFORM_ANDROID2_2:
            certificate = load_certificate(
                FILETYPE_PEM, ANDROID2_2_PEM_FILES[aki].encode()
            )
        if context_type == PLATFORM_ANDROID2_3:
            certificate = load_certificate(
                FILETYPE_PEM, ANDROID2_3_PEM_FILES[aki].encode()
            )
        if context_type == PLATFORM_ANDROID3:
            certificate = load_certificate(
                FILETYPE_PEM, ANDROID3_PEM_FILES[aki].encode()
            )
        if context_type == PLATFORM_ANDROID4:
            certificate = load_certificate(
                FILETYPE_PEM, ANDROID4_PEM_FILES[aki].encode()
            )
        if context_type == PLATFORM_ANDROID4_4:
            certificate = load_certificate(
                FILETYPE_PEM, ANDROID4_4_PEM_FILES[aki].encode()
            )
        if context_type == PLATFORM_ANDROID7:
            certificate = load_certificate(
                FILETYPE_PEM, ANDROID7_PEM_FILES[aki].encode()
            )
        if context_type == PLATFORM_ANDROID8:
            certificate = load_certificate(
                FILETYPE_PEM, ANDROID8_PEM_FILES[aki].encode()
            )
        if context_type == PLATFORM_ANDROID9:
            certificate = load_certificate(
                FILETYPE_PEM, ANDROID9_PEM_FILES[aki].encode()
            )
        if context_type == PLATFORM_ANDROID10:
            certificate = load_certificate(
                FILETYPE_PEM, ANDROID10_PEM_FILES[aki].encode()
            )
        if context_type == PLATFORM_ANDROID11:
            certificate = load_certificate(
                FILETYPE_PEM, ANDROID11_PEM_FILES[aki].encode()
            )
        if context_type == PLATFORM_ANDROID12:
            certificate = load_certificate(
                FILETYPE_PEM, ANDROID12_PEM_FILES[aki].encode()
            )
        if context_type == PLATFORM_ANDROID13:
            certificate = load_certificate(
                FILETYPE_PEM, ANDROID13_PEM_FILES[aki].encode()
            )
        if context_type == PLATFORM_ANDROID14:
            certificate = load_certificate(
                FILETYPE_PEM, ANDROID14_PEM_FILES[aki].encode()
            )
    except KeyError:
        pass
    if certificate is None or not match_certificate(aki, certificate):
        raise FileExistsError(MISSING_MESSAGE)
    return certificate


def get_cn_or_org(certificate: X509) -> str:
    cn_oid = certificate.to_cryptography().subject.get_attributes_for_oid(
        x509.OID_COMMON_NAME
    )
    if cn_oid:
        name = cn_oid[0]._value  # pylint: disable=protected-access
    else:
        name = (
            certificate.to_cryptography()
            .subject.get_attributes_for_oid(x509.OID_ORGANIZATION_NAME)[0]
            ._value
        )  # pylint: disable=protected-access
    return name


def get_leaf(certificates: list[X509]) -> X509:
    new_chain = []
    akis_paris = []
    for cert in certificates:
        common_name = get_cn_or_org(cert)
        aki = get_key_identifier_hex(
            cert.to_cryptography(),
            extension=AuthorityKeyIdentifier,
            key="key_identifier",
        )
        akis_paris.append((aki, cert))
        if common_name[0:1] == "*" or validators.domain(common_name):
            new_chain.append(cert)
    if len(new_chain) == 1:
        return new_chain[0]


def build_chains(leaf: X509, certificates: list[X509]) -> dict:
    roots: list[X509] = []
    chains = {}
    leaf_aki = get_key_identifier_hex(
        leaf.to_cryptography(), extension=AuthorityKeyIdentifier, key="key_identifier"
    )
    aki_lookup = {leaf_aki: [leaf]}
    for cert in certificates:
        aki = get_key_identifier_hex(
            cert.to_cryptography(),
            extension=AuthorityKeyIdentifier,
            key="key_identifier",
        )
        if aki == leaf_aki:
            continue
        aki_lookup.setdefault(aki, [])
        aki_lookup[aki].append(cert)
        for _, context_type in STORES.items():
            try:
                ret = get_certificate_from_store(aki, context_type)
            except FileExistsError:
                continue
            root_ski = get_key_identifier_hex(
                ret.to_cryptography(), extension=SubjectKeyIdentifier, key="digest"
            )
            if root_ski not in [
                get_key_identifier_hex(
                    c.to_cryptography(), extension=SubjectKeyIdentifier, key="digest"
                )
                for c in roots
            ]:
                roots.append(ret)

    def next_chain(ski: str, lookup: dict) -> list[dict]:
        chain = []
        for next_cert in lookup.get(ski, []):
            next_common_name = get_cn_or_org(next_cert)
            next_ski = get_key_identifier_hex(
                next_cert.to_cryptography(),
                extension=SubjectKeyIdentifier,
                key="digest",
            )
            next_aki = get_key_identifier_hex(
                next_cert.to_cryptography(),
                extension=AuthorityKeyIdentifier,
                key="key_identifier",
            )
            chain.append(
                {
                    "certificate": next_cert,
                    "ski": next_ski,
                    "aki": next_aki,
                    "common_name": next_common_name,
                    "next": next_chain(next_ski, lookup),
                }
            )
        return chain

    index = 0
    for cert in roots:
        ski = get_key_identifier_hex(
            cert.to_cryptography(), extension=SubjectKeyIdentifier, key="digest"
        )
        common_name = get_cn_or_org(cert)
        chains[str(index)] = {
            "certificate": cert,
            "ski": ski,
            "common_name": common_name,
            "next": next_chain(ski, aki_lookup),
        }
        index += 1
    return chains


def get_store_result_text(name: str, **kwargs) -> dict:
    short_name = SHORT_LOOKUP.get(name, name)
    trust_status = f"No Root CA Certificate in the {short_name} Trust Store"
    if kwargs.get("exists"):
        trust_status = (
            f"Root CA Certificate present in {short_name} {VERSIONS[name]} Trust Store"
        )
        if name == CCADB:
            trust_status += " (Mozilla, Microsoft, and Apple)"
        if name == PYTHON_CERTIFI:
            trust_status += " (Django, requests, urllib, and anything based from these)"
        if kwargs.get("expired"):
            trust_status += " EXPIRED"

    return trust_status
