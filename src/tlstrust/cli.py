import sys
import logging
import argparse
import ssl
from socket import socket, AF_INET, SOCK_STREAM
from pathlib import Path
from datetime import datetime
from binascii import hexlify
import validators
import idna
from rich.console import Console
from rich.style import Style
from rich.logging import RichHandler
from rich.table import Table
from rich import box
from certifi import where
from OpenSSL import SSL
from OpenSSL.crypto import X509, FILETYPE_PEM, load_certificate
from cryptography.x509 import extensions
from cryptography.x509.base import Certificate
from . import __version__, TrustStore
from .context import SOURCES, PLATFORMS, BROWSERS, LANGUAGES

__module__ = 'tlstrust.cli'

assert sys.version_info >= (3, 9), "Requires Python 3.9 or newer"
logger = logging.getLogger(__name__)
console = Console()
CLI_COLOR_OK = 'dark_sea_green2'
CLI_COLOR_NOK = 'light_coral'
CLI_VALUE_TRUSTED = 'Trusted'
CLI_VALUE_NOT_TRUSTED = 'Not Trusted'

def styled_boolean(value :bool, colors :tuple[str, str] = (CLI_COLOR_OK, CLI_COLOR_NOK)) -> str:
    if not isinstance(value, bool):
        raise TypeError(f'{type(value)} provided')
    color = colors[0] if value else colors[1]
    val = CLI_VALUE_TRUSTED if value else CLI_VALUE_NOT_TRUSTED
    with console.capture() as capture:
        console.print(val, style=Style(color=color))
    return capture.get().strip()

def date_diff(comparer :datetime) -> str:
    interval = comparer - datetime.utcnow()
    if interval.days < -1:
        return f"Expired {int(abs(interval.days))} days ago"
    if interval.days == -1:
        return "Expired yesterday"
    if interval.days == 0:
        return "Expires today"
    if interval.days == 1:
        return "Expires tomorrow"
    if interval.days > 365:
        return f"Expires in {interval.days} days ({int(round(interval.days/365))} years)"
    if interval.days > 1:
        return f"Expires in {interval.days} days"

def output(data :dict) -> Table:
    store :TrustStore = data['trust_store']
    title = f'Root Certificate {data["host"]} ({data["peer_address"]})'
    caption = '\n'.join([
        f'Issuer: {data["certificate_issuer"]}',
        date_diff(data["not_valid_after"]),
    ])
    title_style = Style(bold=True, color=CLI_COLOR_OK if store.is_trusted else CLI_COLOR_NOK)
    table = Table(title=title, caption=caption, title_style=title_style, box=box.SIMPLE)
    table.add_column("Root Trust Store", justify="right", style="dark_turquoise", no_wrap=True)
    table.add_column("Result", justify="left", no_wrap=True)
    contexts = {**SOURCES, **PLATFORMS, **BROWSERS, **LANGUAGES}
    for source_name, source_context in contexts.items():
        is_trusted = store.check_trust(source_context)
        table.add_row(source_name, styled_boolean(is_trusted))
    console.print(table)
    console.print('\n\n')

def get_key_identifier_hex(cert :Certificate, extention :extensions.Extension, key :str) -> str:
    for ext in cert.extensions:
        if isinstance(ext.value, extention):
            return hexlify(getattr(ext.value, key)).decode('utf-8')

def get_root_certificate(peers :list[X509]) -> tuple[X509, str]:
    peers_map = {}
    for cert in peers:
        aki = get_key_identifier_hex(cert.to_cryptography(), extention=extensions.AuthorityKeyIdentifier, key='key_identifier')
        ski = get_key_identifier_hex(cert.to_cryptography(), extention=extensions.SubjectKeyIdentifier, key='digest')
        if ski is None or aki is None:
            logger.warning(f'Certificate {cert.get_subject()} has no SKI or AKI')
            continue
        peers_map[ski] = [cert, aki]
    for cert in peers:
        aki = get_key_identifier_hex(cert.to_cryptography(), extention=extensions.AuthorityKeyIdentifier, key='key_identifier')
        if not aki:
            ski = get_key_identifier_hex(cert.to_cryptography(), extention=extensions.SubjectKeyIdentifier, key='digest')
            return cert, ski
        if aki not in peers_map.keys():
            return cert, aki
    return None, None

def check(host :str, port :int, use_sni :bool = True, client_pem :str = None):
    if not isinstance(port, int):
        raise TypeError(f"provided an invalid type {type(port)} for port, expected int")
    if validators.domain(host) is not True:
        raise ValueError(f"provided an invalid domain {host}")
    if not isinstance(client_pem, str) and client_pem is not None:
        raise TypeError(f"provided an invalid type {type(client_pem)} for client_pem, expected list")
    if not isinstance(use_sni, bool):
        raise TypeError(f"provided an invalid type {type(use_sni)} for tlsext, expected list")

    for method in [
        "SSLv23_METHOD",
        "TLSv1_METHOD",
        "TLSv1_1_METHOD",
        "TLSv1_2_METHOD",
    ]:
        ctx = SSL.Context(method=getattr(SSL, method))
        ctx.load_verify_locations(cafile=where())
        if client_pem:
            client_certificate = load_certificate(FILETYPE_PEM, Path(client_pem).read_bytes())
            logger.debug(f'client certificate issuer: {client_certificate.get_issuer().commonName}')
            ctx.use_certificate(client_certificate)
        ctx.verify_mode = SSL.VERIFY_NONE
        ctx.check_hostname = False
        sock = socket(AF_INET, SOCK_STREAM)
        sock.settimeout(2)
        conn = SSL.Connection(ctx, sock)
        if all([use_sni, ssl.HAS_SNI]):
            logger.info('using SNI')
            conn.set_tlsext_host_name(idna.encode(host))
        certificate_chain = []
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
            conn.close()
            continue
        finally:
            conn.close()
        root_certificate, authority_key_identifier = get_root_certificate(certificate_chain)
        return {
            'host': host,
            'port': port,
            'peer_address': peer_address,
            'not_valid_after': root_certificate.to_cryptography().not_valid_after,
            'certificate_issuer': root_certificate.get_issuer().commonName or root_certificate.get_issuer().organizationName,
            'trust_store': TrustStore(authority_key_identifier)
        }

def cli():
    parser = argparse.ArgumentParser()
    parser.add_argument("targets", nargs="*", help='All unnamed arguments are hosts (and ports) targets to test. ~$ tlstrust apple.com:443 github.io localhost:3000')
    parser.add_argument('-H', '--host', help='single host to check', dest='host', default=None)
    parser.add_argument('-p', '--port', help='TLS port of host', dest='port', default=443)
    parser.add_argument('-C', '--client-pem', help='path to PEM encoded client certificate, url or file path accepted', dest='client_pem', default=None)
    parser.add_argument('--disable-sni', help='Do not negotiate SNI using INDA encoded host', dest='disable_sni', action="store_true")
    parser.add_argument('-v', '--errors-only', help='set logging level to ERROR (default CRITICAL)', dest='log_level_error', action="store_true")
    parser.add_argument('-vv', '--warning', help='set logging level to WARNING (default CRITICAL)', dest='log_level_warning', action="store_true")
    parser.add_argument('-vvv', '--info', help='set logging level to INFO (default CRITICAL)', dest='log_level_info', action="store_true")
    parser.add_argument('-vvvv', '--debug', help='set logging level to DEBUG (default CRITICAL)', dest='log_level_debug', action="store_true")
    parser.add_argument('--version', dest='show_version', action="store_true")
    args = parser.parse_args()

    log_level = logging.CRITICAL
    if args.log_level_error:
        log_level = logging.ERROR
    if args.log_level_warning:
        log_level = logging.WARNING
    if args.log_level_info:
        log_level = logging.INFO
    if args.log_level_debug:
        log_level = logging.DEBUG
    handlers = []
    log_format = '%(asctime)s - %(name)s - [%(levelname)s] %(message)s'
    if sys.stdout.isatty():
        log_format = '%(message)s'
        handlers.append(RichHandler(rich_tracebacks=True))
    logging.basicConfig(
        format=log_format,
        level=log_level,
        handlers=handlers
    )
    def version(): import platform; print(f"{__version__} Python {sys.version} {platform.platform()} {platform.uname().node} {platform.uname().release} {platform.version()}")
    if args.show_version:
        version()
        sys.exit(0)
    if args.host is None and len(args.targets) == 0:
        version()
        parser.print_help(sys.stderr)
        sys.exit(1)
    if args.host is not None:
        args.targets.append(f'{args.host}:{args.port}')

    domains = []
    for target in args.targets:
        pieces = target.split(':')
        host, port = None, None
        if len(pieces) == 2:
            host, port = pieces
        if len(pieces) == 1:
            host = pieces[0]
            port = args.port
        if validators.domain(host) is not True:
            raise AttributeError(f'host {host} is invalid')
        domains.append((host, int(port)))

    all_results = []
    evaluation_start = datetime.utcnow()

    for domain, port in domains:
        result = check(
            domain,
            int(port),
            use_sni=not args.disable_sni,
            client_pem=args.client_pem,
        )
        if result:
            all_results.append(result)
    valid = all([v['trust_store'].is_trusted for v in all_results])
    for result in all_results:
        output(result)
    result_style = Style(color=CLI_COLOR_OK if valid else CLI_COLOR_NOK)
    console.print('Trusted ✓✓✓' if valid else '\nNot Trusted', style=result_style)
    console.print(f'Evaluation duration seconds {(datetime.utcnow() - evaluation_start).total_seconds()}\n\n')
