from OpenSSL.crypto import FILETYPE_PEM
from tlstrust import TrustStore
from tlstrust import context

ca_common_name = 'DigiCert Global Root G3'

def test_setup():
    ts = TrustStore(ca_common_name=ca_common_name)
    assert isinstance(ts, TrustStore)
    assert isinstance(ts.is_trusted, bool)

def test_context_ccadb():
    ts = TrustStore(ca_common_name=ca_common_name)
    assert isinstance(ts.check_trust(context.SOURCE_CCADB), bool)
    assert isinstance(ts.ccadb, bool)

def test_context_apple():
    ts = TrustStore(ca_common_name=ca_common_name)
    assert isinstance(ts.check_trust(context.SOURCE_APPLE), bool)
    assert isinstance(ts.apple, bool)

def test_context_android():
    ts = TrustStore(ca_common_name=ca_common_name)
    assert isinstance(ts.check_trust(context.SOURCE_ANDROID), bool)
    assert isinstance(ts.android, bool)
    assert isinstance(ts.android_latest, bool)
    assert isinstance(ts.check_trust(context.PLATFORM_ANDROID7), bool)
    assert isinstance(ts.android7, bool)
    assert isinstance(ts.check_trust(context.PLATFORM_ANDROID8), bool)
    assert isinstance(ts.android8, bool)
    assert isinstance(ts.check_trust(context.PLATFORM_ANDROID9), bool)
    assert isinstance(ts.android9, bool)
    assert isinstance(ts.check_trust(context.PLATFORM_ANDROID10), bool)
    assert isinstance(ts.android10, bool)
    assert isinstance(ts.check_trust(context.PLATFORM_ANDROID11), bool)
    assert isinstance(ts.android11, bool)
    assert isinstance(ts.check_trust(context.PLATFORM_ANDROID12), bool)
    assert isinstance(ts.android12, bool)

def test_context_linux():
    ts = TrustStore(ca_common_name=ca_common_name)
    assert isinstance(ts.check_trust(context.SOURCE_LINUX), bool)
    assert isinstance(ts.linux, bool)

def test_context_java():
    ts = TrustStore(ca_common_name=ca_common_name)
    assert isinstance(ts.check_trust(context.SOURCE_JAVA), bool)
    assert isinstance(ts.java, bool)

def test_context_platforms():
    ts = TrustStore(ca_common_name=ca_common_name)
    assert isinstance(ts.check_trust(context.PLATFORM_ANDROID), bool)
    assert isinstance(ts.check_trust(context.PLATFORM_LINUX), bool)
    assert isinstance(ts.check_trust(context.PLATFORM_JAVA), bool)
    assert isinstance(ts.check_trust(context.PLATFORM_WINDOWS), bool)
    assert isinstance(ts.check_trust(context.PLATFORM_APPLE), bool)

def test_context_browsers():
    ts = TrustStore(ca_common_name=ca_common_name)
    assert isinstance(ts.check_trust(context.BROWSER_AMAZON_SILK), bool)
    assert isinstance(ts.check_trust(context.BROWSER_BRAVE), bool)
    assert isinstance(ts.check_trust(context.BROWSER_CHROMIUM), bool)
    assert isinstance(ts.check_trust(context.BROWSER_FIREFOX), bool)
    assert isinstance(ts.check_trust(context.BROWSER_GOOGLE_CHROME), bool)
    assert isinstance(ts.check_trust(context.BROWSER_MICROSOFT_EDGE), bool)
    assert isinstance(ts.check_trust(context.BROWSER_OPERA), bool)
    assert isinstance(ts.check_trust(context.BROWSER_SAFARI), bool)
    assert isinstance(ts.check_trust(context.BROWSER_SAMSUNG_INTERNET_BROWSER), bool)
    assert isinstance(ts.check_trust(context.BROWSER_YANDEX_BROWSER), bool)
    assert isinstance(ts.check_trust(context.BROWSER_VIVALDI), bool)
    assert isinstance(ts.check_trust(context.BROWSER_TOR_BROWSER), bool)

def test_context_python():
    ts = TrustStore(ca_common_name=ca_common_name)
    assert isinstance(ts.check_trust(context.PYTHON_WINDOWS_SERVER), bool)
    assert isinstance(ts.check_trust(context.PYTHON_LINUX_SERVER), bool)
    assert isinstance(ts.check_trust(context.PYTHON_MACOS_SERVER), bool)
    assert isinstance(ts.check_trust(context.PYTHON_CERTIFI), bool)
    assert isinstance(ts.check_trust(context.PYTHON_URLLIB), bool)
    assert isinstance(ts.check_trust(context.PYTHON_REQUESTS), bool)
    assert isinstance(ts.check_trust(context.PYTHON_DJANGO), bool)
