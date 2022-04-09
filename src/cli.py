import sys
import logging
import argparse
from datetime import datetime
from pathlib import Path
import validators
from rich.console import Console
from rich.style import Style
from rich.logging import RichHandler
from rich.table import Table
from rich import box
from OpenSSL.crypto import FILETYPE_PEM, load_certificate
from cryptography import x509
from tlstrust import __version__, TrustStore, trust_stores_from_chain
from tlstrust.util import get_certificate_chain

__module__ = 'tlstrust.cli'

assert sys.version_info >= (3, 9), "Requires Python 3.9 or newer"
logger = logging.getLogger(__name__)
console = Console()
CLI_COLOR_OK = 'dark_sea_green2'
CLI_COLOR_NOK = 'light_coral'
CLI_VALUE_TRUSTED = 'Trusted'
CLI_VALUE_NOT_TRUSTED = 'Not Trusted'
DEFAULT_PORT = 443

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

def output(store :TrustStore) -> Table:
    subject_common_name = store.certificate.to_cryptography().subject.get_attributes_for_oid(x509.OID_COMMON_NAME)[0].value.strip()
    title = f'{"Trusted ✓✓✓" if store.is_trusted else "Not Trusted"}\nRoot Certificate {subject_common_name}\n{date_diff(store.certificate.to_cryptography().not_valid_after)}'
    caption = f'SKI {store.key_identifier}'
    title_style = Style(bold=True, color=CLI_COLOR_OK if store.is_trusted else CLI_COLOR_NOK)
    table = Table(title=title, caption=caption, title_style=title_style, box=box.SIMPLE)
    table.add_column("Root Trust Store", justify="right", style="dark_turquoise", no_wrap=True)
    table.add_column("Result", justify="left", no_wrap=True)
    for name, is_trusted in store.all_results.items():
        table.add_row(name, styled_boolean(is_trusted))
    console.print(table)
    console.print()

def cli():
    parser = argparse.ArgumentParser()
    parser.add_argument("targets", nargs="*", help='All unnamed arguments are hosts (and ports) targets to test. ~$ tlstrust apple.com:443 github.io localhost:3000')
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
    if len(args.targets) == 0:
        parser.print_help(sys.stderr)
        sys.exit(1)

    if args.client_pem:
        client_certificate = load_certificate(FILETYPE_PEM, Path(args.client_pem).read_bytes())
        logger.debug(f'client certificate issuer: {client_certificate.get_issuer().commonName}')

    evaluation_start = datetime.utcnow()
    domains = []
    for target in args.targets:
        pieces = target.split(':')
        host, port = None, None
        if len(pieces) == 2:
            host, port = pieces
        if len(pieces) == 1:
            host = pieces[0]
            port = DEFAULT_PORT
        if validators.domain(host) is not True:
            raise AttributeError(f'host {host} is invalid')
        domains.append((host, int(port)))

    for domain, port in domains:
        chain, peer_addr = get_certificate_chain(domain, int(port), use_sni=not args.disable_sni)
        console.print(f'{host}:{port} ({peer_addr})')
        for trust_store in trust_stores_from_chain(chain):
            output(trust_store)
    console.print(f'Evaluation duration seconds {(datetime.utcnow() - evaluation_start).total_seconds()}')

if __name__ == "__main__":
    cli()
