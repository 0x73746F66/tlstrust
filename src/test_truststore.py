import pytest
from OpenSSL.crypto import X509
from tlstrust import TrustStore
from tlstrust import context

good_ca_common_name = 'DigiCert Global Root G3'
bad_ca_common_name = 'DST Root CA X3'

def test_cert_properties():
    ts = TrustStore(ca_common_name=bad_ca_common_name)
    assert isinstance(ts, TrustStore)
    assert isinstance(ts.subject_key_identifier, str)
    ts = TrustStore(ca_common_name=good_ca_common_name)
    assert isinstance(ts, TrustStore)
    assert isinstance(ts.subject_key_identifier, str)

def test_cert_exists():
    def _test(ts :TrustStore):
        assert ts.exists(context_type=context.SOURCE_CCADB)
        assert ts.exists(context_type=context.SOURCE_APPLE)
        assert ts.exists(context_type=context.SOURCE_ANDROID)
        assert ts.exists(context_type=context.SOURCE_JAVA)
        assert ts.exists(context_type=context.SOURCE_CERTIFI)
    ts = TrustStore(ca_common_name=good_ca_common_name)
    _test(ts)
    assert ts.exists(context_type=context.SOURCE_LINUX)
    ts = TrustStore(ca_common_name=bad_ca_common_name)
    _test(ts)
    assert ts.exists(context_type=context.SOURCE_LINUX) is False


def test_cert_retrieval():
    def _test(ts :TrustStore):
        assert isinstance(ts.get_certificate_from_store(context_type=context.SOURCE_CCADB), X509)
        assert isinstance(ts.get_certificate_from_store(context_type=context.SOURCE_ANDROID), X509)
        assert isinstance(ts.get_certificate_from_store(context_type=context.SOURCE_JAVA), X509)
        assert isinstance(ts.get_certificate_from_store(context_type=context.SOURCE_CERTIFI), X509)
        with pytest.raises(NotImplementedError):
            ts.get_certificate_from_store(context_type=context.SOURCE_APPLE)

    ts = TrustStore(ca_common_name=good_ca_common_name)
    _test(ts)
    assert isinstance(ts.get_certificate_from_store(context_type=context.SOURCE_LINUX), X509)
    ts = TrustStore(ca_common_name=bad_ca_common_name)
    _test(ts)
    with pytest.raises(FileExistsError):
        ts.get_certificate_from_store(context_type=context.SOURCE_LINUX)

def test_expired_in_store():
    def _test(ts :TrustStore):
        assert isinstance(ts.expired_in_store(context_type=context.SOURCE_CCADB), bool)
        assert isinstance(ts.expired_in_store(context_type=context.SOURCE_ANDROID), bool)
        assert isinstance(ts.expired_in_store(context_type=context.SOURCE_JAVA), bool)
        assert isinstance(ts.expired_in_store(context_type=context.SOURCE_CERTIFI), bool)
    ts = TrustStore(ca_common_name=bad_ca_common_name)
    _test(ts)
    with pytest.raises(FileExistsError):
        ts.expired_in_store(context_type=context.SOURCE_APPLE)
        ts.expired_in_store(context_type=context.SOURCE_LINUX)
    ts = TrustStore(ca_common_name=good_ca_common_name)
    _test(ts)
    assert isinstance(ts.expired_in_store(context_type=context.SOURCE_APPLE), bool)
    assert isinstance(ts.expired_in_store(context_type=context.SOURCE_LINUX), bool)

def test_cert_retrieval_apple():
    ts = TrustStore(ca_common_name=good_ca_common_name)
    with pytest.raises(NotImplementedError):
        ts.get_certificate_from_store(context_type=context.SOURCE_APPLE)
    ts = TrustStore(ca_common_name=bad_ca_common_name)
    with pytest.raises(NotImplementedError):
        ts.get_certificate_from_store(context_type=context.SOURCE_APPLE)

def test_cn_property():
    def _test(ca_common_name):
        result = TrustStore(ca_common_name=ca_common_name)
        assert isinstance(result, TrustStore)
        assert isinstance(result.ca_common_name, str)
    _test(bad_ca_common_name)
    _test(good_ca_common_name)

def test_no_args():
    with pytest.raises(TypeError):
        TrustStore()

def test_no_none_args():
    with pytest.raises(TypeError):
        TrustStore(None, None)

def test_ca_common_name_type():
    with pytest.raises(TypeError):
        TrustStore(ca_common_name=False)

def test_authority_key_identifier_type():
    with pytest.raises(TypeError):
        TrustStore(authority_key_identifier=False)

def test_pem_format():
    ts = TrustStore(ca_common_name=good_ca_common_name)
    assert isinstance(ts.check_trust(), bool)
    ts = TrustStore(ca_common_name=bad_ca_common_name)
    assert isinstance(ts.check_trust(), bool)

def test_check_context_type():
    ts = TrustStore(ca_common_name=good_ca_common_name)
    with pytest.raises(TypeError):
        ts.check_trust('apple')
    ts = TrustStore(ca_common_name=bad_ca_common_name)
    with pytest.raises(TypeError):
        ts.check_trust('apple')

def test_check_bad_context():
    ts = TrustStore(ca_common_name=good_ca_common_name)
    with pytest.raises(AttributeError):
        ts.check_trust(99999)
    ts = TrustStore(ca_common_name=bad_ca_common_name)
    with pytest.raises(AttributeError):
        ts.check_trust(99999)

def test_result():
    ts = TrustStore(ca_common_name=good_ca_common_name)
    assert ts.ccadb
    assert ts.apple
    assert ts.android
    assert ts.java
    assert ts.linux
    assert ts.certifi
    ts = TrustStore(ca_common_name=bad_ca_common_name)
    assert ts.ccadb is False
    assert ts.apple is False
    assert ts.android is False
    assert ts.java is False
    assert ts.linux is False
    assert ts.certifi is False
