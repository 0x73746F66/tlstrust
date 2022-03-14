from OpenSSL.crypto import FILETYPE_PEM
from tlstrust import TrustStore
from tlstrust import context

good_ski = 'bf5fb7d1cedd1f86f45b55acdcd710c20ea988e7'

def test_setup():
    ts = TrustStore(authority_key_identifier=good_ski)
    assert isinstance(ts, TrustStore)
    assert isinstance(ts.is_trusted, bool)

def test_context_ccadb():
    ts = TrustStore(authority_key_identifier=good_ski)
    assert isinstance(ts.check_trust(context.SOURCE_CCADB), bool)
    assert isinstance(ts.ccadb, bool)

def test_context_android():
    ts = TrustStore(authority_key_identifier=good_ski)
    assert isinstance(ts.check_trust(context.SOURCE_ANDROID), bool)
    assert isinstance(ts.android, bool)
    assert isinstance(ts.android_latest, bool)
    assert isinstance(ts.check_trust(context.PLATFORM_ANDROID7), bool)
    assert isinstance(ts.android7, bool)
    assert isinstance(ts.check_trust(context.PLATFORM_ANDROID2_2), bool)
    assert isinstance(ts.android2_2, bool)
    assert isinstance(ts.check_trust(context.PLATFORM_ANDROID2_3), bool)
    assert isinstance(ts.android2_3, bool)
    assert isinstance(ts.check_trust(context.PLATFORM_ANDROID3), bool)
    assert isinstance(ts.android3, bool)
    assert isinstance(ts.check_trust(context.PLATFORM_ANDROID4), bool)
    assert isinstance(ts.android4, bool)
    assert isinstance(ts.check_trust(context.PLATFORM_ANDROID4_4), bool)
    assert isinstance(ts.android4_4, bool)
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
    ts = TrustStore(authority_key_identifier=good_ski)
    assert isinstance(ts.check_trust(context.SOURCE_LINUX), bool)
    assert isinstance(ts.linux, bool)

def test_context_java():
    ts = TrustStore(authority_key_identifier=good_ski)
    assert isinstance(ts.check_trust(context.SOURCE_JAVA), bool)
    assert isinstance(ts.java, bool)

def test_context_russia():
    ts = TrustStore(authority_key_identifier=good_ski)
    assert isinstance(ts.check_trust(context.SOURCE_RUSSIA), bool)
    assert isinstance(ts.russia, bool)

def test_context_platforms():
    ts = TrustStore(authority_key_identifier=good_ski)
    assert isinstance(ts.check_trust(context.PLATFORM_ANDROID), bool)
    assert isinstance(ts.check_trust(context.PLATFORM_LINUX), bool)
    assert isinstance(ts.check_trust(context.PLATFORM_JAVA), bool)
    assert isinstance(ts.check_trust(context.PLATFORM_WINDOWS), bool)
    assert isinstance(ts.check_trust(context.PLATFORM_RUSSIA), bool)

def test_context_browsers():
    ts = TrustStore(authority_key_identifier=good_ski)
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
    ts = TrustStore(authority_key_identifier=good_ski)
    assert isinstance(ts.check_trust(context.PYTHON_WINDOWS_SERVER), bool)
    assert isinstance(ts.check_trust(context.PYTHON_LINUX_SERVER), bool)
    assert isinstance(ts.check_trust(context.PYTHON_MACOS_SERVER), bool)
    assert isinstance(ts.check_trust(context.PYTHON_CERTIFI), bool)
    assert isinstance(ts.check_trust(context.PYTHON_URLLIB), bool)
    assert isinstance(ts.check_trust(context.PYTHON_REQUESTS), bool)
    assert isinstance(ts.check_trust(context.PYTHON_DJANGO), bool)
