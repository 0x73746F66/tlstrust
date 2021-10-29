import pytest
from OpenSSL.crypto import X509
from tlstrust import TrustStore
from tlstrust import context

good_ski = 'b3db48a4f9a1c5d8ae3641cc1163696229bc4bc6'
bad_ski = 'c4a7b1a47b2c71fadbe14b9075ffc41560858910'

def test_properties():
    def _test(aki):
        ts = TrustStore(authority_key_identifier=aki)
        assert isinstance(ts, TrustStore)
        assert isinstance(ts.key_identifier, str)
        assert isinstance(ts.ski_match, bool)
        assert ts.key_identifier == aki
        return ts
    
    _test(bad_ski)
    ts = _test(good_ski)
    assert ts.key_identifier == good_ski
    assert ts.ski_match


def test_cert_exists():
    def _test(ts :TrustStore):
        assert ts.exists(context_type=context.SOURCE_CCADB)
        assert ts.exists(context_type=context.SOURCE_ANDROID)
        assert ts.exists(context_type=context.SOURCE_JAVA)
        assert ts.exists(context_type=context.SOURCE_CERTIFI)
    ts = TrustStore(authority_key_identifier=good_ski)
    _test(ts)
    assert ts.exists(context_type=context.SOURCE_LINUX)
    ts = TrustStore(authority_key_identifier=bad_ski)
    _test(ts)
    assert ts.exists(context_type=context.SOURCE_LINUX) is False


def test_cert_retrieval():
    def _test(ts :TrustStore):
        assert isinstance(ts.get_certificate_from_store(context_type=context.SOURCE_CCADB), X509)
        assert isinstance(ts.get_certificate_from_store(context_type=context.SOURCE_ANDROID), X509)
        assert isinstance(ts.get_certificate_from_store(context_type=context.SOURCE_JAVA), X509)
        assert isinstance(ts.get_certificate_from_store(context_type=context.SOURCE_CERTIFI), X509)

    ts = TrustStore(authority_key_identifier=good_ski)
    _test(ts)
    assert isinstance(ts.get_certificate_from_store(context_type=context.SOURCE_LINUX), X509)
    ts = TrustStore(authority_key_identifier=bad_ski)
    _test(ts)
    with pytest.raises(FileExistsError):
        ts.get_certificate_from_store(context_type=context.SOURCE_LINUX)

def test_expired_in_store():
    def _test(ts :TrustStore):
        assert isinstance(ts.expired_in_store(context_type=context.SOURCE_CCADB), bool)
        assert isinstance(ts.expired_in_store(context_type=context.SOURCE_ANDROID), bool)
        assert isinstance(ts.expired_in_store(context_type=context.SOURCE_JAVA), bool)
        assert isinstance(ts.expired_in_store(context_type=context.SOURCE_CERTIFI), bool)
    ts = TrustStore(authority_key_identifier=bad_ski)
    _test(ts)
    with pytest.raises(FileExistsError):
        ts.expired_in_store(context_type=context.SOURCE_LINUX)
    ts = TrustStore(authority_key_identifier=good_ski)
    _test(ts)
    assert isinstance(ts.expired_in_store(context_type=context.SOURCE_LINUX), bool)

def test_no_args():
    with pytest.raises(TypeError):
        TrustStore()

def test_no_none_args():
    with pytest.raises(TypeError):
        TrustStore(None, None)

def test_key_identifier_type():
    with pytest.raises(TypeError):
        TrustStore(authority_key_identifier=False)

def test_pem_format():
    ts = TrustStore(authority_key_identifier=good_ski)
    assert isinstance(ts.check_trust(), bool)
    ts = TrustStore(authority_key_identifier=bad_ski)
    assert isinstance(ts.check_trust(), bool)
def test_check_bad_context():
    ts = TrustStore(authority_key_identifier=good_ski)
    with pytest.raises(AttributeError):
        ts.check_trust(99999)
    ts = TrustStore(authority_key_identifier=bad_ski)
    with pytest.raises(AttributeError):
        ts.check_trust(99999)

def test_result():
    ts = TrustStore(authority_key_identifier=good_ski)
    assert ts.ccadb
    assert ts.android
    assert ts.java
    assert ts.linux
    assert ts.certifi
    ts = TrustStore(authority_key_identifier=bad_ski)
    assert ts.ccadb is False
    assert ts.android is False
    assert ts.java is False
    assert ts.linux is False
    assert ts.certifi is False
