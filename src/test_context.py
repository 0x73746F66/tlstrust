from OpenSSL.crypto import FILETYPE_PEM
from tlstrust import TrustStore
from tlstrust import context

pem = """
-----BEGIN CERTIFICATE-----
MIIBtjCCAVugAwIBAgITBmyf1XSXNmY/Owua2eiedgPySjAKBggqhkjOPQQDAjA5
MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24g
Um9vdCBDQSAzMB4XDTE1MDUyNjAwMDAwMFoXDTQwMDUyNjAwMDAwMFowOTELMAkG
A1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJvb3Qg
Q0EgMzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCmXp8ZBf8ANm+gBG1bG8lKl
ui2yEujSLtf6ycXYqm0fc4E7O5hrOXwzpcVOho6AF2hiRVd9RFgdszflZwjrZt6j
QjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBSr
ttvXBp43rDCGB5Fwx5zEGbF4wDAKBggqhkjOPQQDAgNJADBGAiEA4IWSoxe3jfkr
BqWTrBqYaGFy+uGh0PsceGCmQ5nFuMQCIQCcAu/xlJyzlvnrxir4tiz+OpAUFteM
YyRIHN8wfdVoOw==
-----END CERTIFICATE-----"""

def test_setup():
    ts = TrustStore(FILETYPE_PEM, pem)
    assert isinstance(ts, TrustStore)
    assert isinstance(ts.fingerprint_sha256, str)
    assert isinstance(ts.fingerprint_sha1, str)

def test_context_ccadb():
    ts = TrustStore(FILETYPE_PEM, pem)
    assert isinstance(ts.is_trusted(context.SOURCE_CCADB), bool)
    assert isinstance(ts.trusted_by_ccadb(), bool)

def test_context_apple():
    ts = TrustStore(FILETYPE_PEM, pem)
    assert isinstance(ts.is_trusted(context.SOURCE_APPLE), bool)
    assert isinstance(ts.trusted_by_apple(), bool)

def test_context_android():
    ts = TrustStore(FILETYPE_PEM, pem)
    assert isinstance(ts.is_trusted(context.SOURCE_ANDROID), bool)
    assert isinstance(ts.trusted_by_android(), bool)

def test_context_linux():
    ts = TrustStore(FILETYPE_PEM, pem)
    assert isinstance(ts.is_trusted(context.SOURCE_LINUX), bool)
    assert isinstance(ts.trusted_by_linux(), bool)

def test_context_java():
    ts = TrustStore(FILETYPE_PEM, pem)
    assert isinstance(ts.is_trusted(context.SOURCE_JAVA), bool)
    assert isinstance(ts.trusted_by_java(), bool)

def test_context_platforms():
    ts = TrustStore(FILETYPE_PEM, pem)
    assert isinstance(ts.is_trusted(context.PLATFORM_ANDROID), bool)
    assert isinstance(ts.is_trusted(context.PLATFORM_LINUX), bool)
    assert isinstance(ts.is_trusted(context.PLATFORM_JAVA), bool)
    assert isinstance(ts.is_trusted(context.PLATFORM_WINDOWS), bool)
    assert isinstance(ts.is_trusted(context.PLATFORM_APPLE), bool)

def test_context_browsers():
    ts = TrustStore(FILETYPE_PEM, pem)
    assert isinstance(ts.is_trusted(context.BROWSER_AMAZON_SILK), bool)
    assert isinstance(ts.is_trusted(context.BROWSER_BRAVE), bool)
    assert isinstance(ts.is_trusted(context.BROWSER_CHROMIUM), bool)
    assert isinstance(ts.is_trusted(context.BROWSER_FIREFOX), bool)
    assert isinstance(ts.is_trusted(context.BROWSER_GOOGLE_CHROME), bool)
    assert isinstance(ts.is_trusted(context.BROWSER_MICROSOFT_EDGE), bool)
    assert isinstance(ts.is_trusted(context.BROWSER_OPERA), bool)
    assert isinstance(ts.is_trusted(context.BROWSER_SAFARI), bool)
    assert isinstance(ts.is_trusted(context.BROWSER_SAMSUNG_INTERNET_BROWSER), bool)
    assert isinstance(ts.is_trusted(context.BROWSER_YANDEX_BROWSER), bool)
    assert isinstance(ts.is_trusted(context.BROWSER_VIVALDI), bool)
    assert isinstance(ts.is_trusted(context.BROWSER_TOR_BROWSER), bool)

def test_context_python():
    ts = TrustStore(FILETYPE_PEM, pem)
    assert isinstance(ts.is_trusted(context.PYTHON_WINDOWS_SERVER), bool)
    assert isinstance(ts.is_trusted(context.PYTHON_LINUX_SERVER), bool)
    assert isinstance(ts.is_trusted(context.PYTHON_MACOS_SERVER), bool)
    assert isinstance(ts.is_trusted(context.PYTHON_CERTIFI), bool)
    assert isinstance(ts.is_trusted(context.PYTHON_URLLIB), bool)
    assert isinstance(ts.is_trusted(context.PYTHON_REQUESTS), bool)
    assert isinstance(ts.is_trusted(context.PYTHON_DJANGO), bool)
