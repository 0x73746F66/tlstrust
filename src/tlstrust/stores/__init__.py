from tlstrust import context
from .ccadb import __version__ as ccadb_version
from .java import __version__ as java_version
from .certifi import __version__ as certifi_version
from .mintsifry_rossii import __version__ as russia_version
from .rustls import __version__ as rust_version
from .curl import __version__ as curl_version
from .dart import __version__ as dart_version
from .android_2_2 import __version__ as android2_2_version
from .android_2_3 import __version__ as android2_3_version
from .android_3 import __version__ as android3_version
from .android_4 import __version__ as android4_version
from .android_4_4 import __version__ as android4_4_version
from .android_7 import __version__ as android7_version
from .android_8 import __version__ as android8_version
from .android_9 import __version__ as android9_version
from .android_10 import __version__ as android10_version
from .android_11 import __version__ as android11_version
from .android_12 import __version__ as android12_version
from .android_13 import __version__ as android13_version
from .android_14 import __version__ as android14_version
from .android_latest import __version__ as android_version


__module__ = "tlstrust.stores"

VERSIONS = {
    context.CCADB: ccadb_version,
    context.JAVA_SRE: java_version,
    context.ANDROID: android_version,
    context.ANDROID_LATEST: android_version,
    context.GOOGLE_TRUST_SERVICES: android_version,
    context.ANDROID_FROYO: android2_2_version,
    context.ANDROID_GINGERBREAD: android2_3_version,
    context.ANDROID_HONEYCOMB: android3_version,
    context.ANDROID_ICE_CREAM_SANDWICH: android4_version,
    context.ANDROID_KITKAT: android4_4_version,
    context.ANDROID_NOUGAT: android7_version,
    context.ANDROID_OREO: android8_version,
    context.ANDROID_PIE: android9_version,
    context.ANDROID_QUINCE_TART: android10_version,
    context.ANDROID_RED_VELVET_CAKE: android11_version,
    context.ANDROID_SNOW_CONE: android12_version,
    context.ANDROID_TIRAMISU: android13_version,
    context.ANDROID_UPSIDE_DOWN_CAKE: android14_version,
    context.LINUX_ARCH: ccadb_version,
    context.LINUX_FEDORA: ccadb_version,
    context.LINUX_DEBIAN: ccadb_version,
    context.LINUX_UBUNTU: ccadb_version,
    context.LINUX_ALPINE: ccadb_version,
    context.LINUX_CENTOS: ccadb_version,
    context.LINUX_RHEL: ccadb_version,
    context.LINUX_OPENBSD: ccadb_version,
    context.LINUX_FREEBSD: ccadb_version,
    context.PYTHON_CERTIFI: certifi_version,
    context.MINTSIFRY_ROSSII: russia_version,
    context.RUSTLS: rust_version,
    context.CURL: curl_version,
    context.DART: dart_version,
    context.ELIXIR_WINDOWS: curl_version,
    context.ELIXIR_LINUX: curl_version,
    context.ELIXIR_APPLE: curl_version,
    context.ELIXIR_MINT: curl_version,
    context.ELIXIR_PHOENIX_WINDOWS: curl_version,
    context.ELIXIR_PHOENIX_LINUX: curl_version,
    context.ELIXIR_PHOENIX_MACOS: curl_version,
    context.PYTHON: certifi_version,
    context.WINDOWS: ccadb_version,
    context.APPLE: ccadb_version,
    context.FIREFOX: ccadb_version,
    context.TOR: ccadb_version,
    context.CHROMIUM: ccadb_version,
    context.CHROME: ccadb_version,
    context.EDGE: ccadb_version,
    context.BRAVE: ccadb_version,
    context.OPERA: ccadb_version,
    context.VIVALDI: ccadb_version,
    context.SILK: ccadb_version,
    context.SAMSUNG: ccadb_version,
    context.YANDEX: russia_version,
    context.SAFARI: ccadb_version,
    context.ROKU: ccadb_version,
    context.PY_WINDOWS: ccadb_version,
    context.PY_LINUX: ccadb_version,
    context.PY_APPLE: ccadb_version,
    context.PY_CERTIFI: certifi_version,
    context.PY_URLLIB: certifi_version,
    context.PY_REQUESTS: certifi_version,
    context.PY_DJANGO: certifi_version,
    context.RUST_WINDOWS: rust_version,
    context.RUST_LINUX: rust_version,
    context.RUST_APPLE: rust_version,
    context.RUST_RUSTLS: rust_version,
    context.RUST_WEBPKI: rust_version,
    context.ERLANG_WINDOWS: ccadb_version,
    context.ERLANG_LINUX: ccadb_version,
    context.ERLANG_APPLE: ccadb_version,
    context.ERLANG_CERTIFI: certifi_version,
    context.GO_WINDOWS: ccadb_version,
    context.GO_LINUX: ccadb_version,
    context.GO_APPLE: ccadb_version,
    context.GO_CERTIFI: certifi_version,
    context.NODE_WINDOWS: ccadb_version,
    context.NODE_LINUX: ccadb_version,
    context.NODE_APPLE: ccadb_version,
    context.NODE_CERTIFI: certifi_version,
    context.RUBY_WINDOWS: ccadb_version,
    context.RUBY_LINUX: ccadb_version,
    context.RUBY_APPLE: ccadb_version,
    context.RUBY_CERTIFI: certifi_version,
    context.CURL_WINDOWS: curl_version,
    context.CURL_LINUX: curl_version,
    context.CURL_APPLE: curl_version,
}
