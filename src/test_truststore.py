import pytest
from OpenSSL.crypto import X509
from tlstrust import TrustStore, trust_stores_from_chain
from tlstrust import context, util

rus_ski = "29bdb1aad5d93b21d8dc4c0efe11e7760b2fc0f6"
good_ski = "bf5fb7d1cedd1f86f45b55acdcd710c20ea988e7"
bad_ski = "c4a7b1a47b2c71fadbe14b9075ffc41560858910"
missing_ski = "noop"
host = "ssllabs.com"


def test_properties():
    def _test(aki):
        ts = TrustStore(authority_key_identifier=aki)
        assert isinstance(ts, TrustStore)
        assert isinstance(ts.key_identifier, str)
        assert isinstance(ts.certificate, X509)
        assert ts.key_identifier == aki
        return ts

    _test(bad_ski)
    ts = _test(good_ski)
    assert ts.key_identifier == good_ski


def test_cert_exists():
    ts = TrustStore(authority_key_identifier=good_ski)
    assert ts.exists(context_type=context.SOURCE_ANDROID)
    assert ts.exists(context_type=context.SOURCE_CERTIFI)
    assert ts.exists(context_type=context.SOURCE_JAVA)
    assert ts.exists(context_type=context.SOURCE_CCADB)
    assert ts.exists(context_type=context.SOURCE_CURL)
    assert ts.exists(context_type=context.SOURCE_RUSTLS)
    assert ts.exists(context_type=context.SOURCE_DART)
    assert ts.exists(context_type=context.PLATFORM_ANDROID12)
    assert ts.exists(context_type=context.PLATFORM_ANDROID11)
    assert ts.exists(context_type=context.PLATFORM_ANDROID10)
    assert ts.exists(context_type=context.PLATFORM_ANDROID9)
    assert ts.exists(context_type=context.PLATFORM_ANDROID8)
    assert ts.exists(context_type=context.PLATFORM_ANDROID7)
    assert ts.exists(context_type=context.PLATFORM_ANDROID4_4)
    assert ts.exists(context_type=context.PLATFORM_ANDROID4)
    assert ts.exists(context_type=context.PLATFORM_ANDROID3)
    assert ts.exists(context_type=context.PLATFORM_ANDROID2_3)
    assert ts.exists(context_type=context.PLATFORM_ANDROID2_2)
    assert ts.exists(context_type=context.SOURCE_RUSSIA) is False

    ts = TrustStore(authority_key_identifier=rus_ski)
    assert ts.exists(context_type=context.SOURCE_RUSSIA)
    with pytest.raises(AttributeError):
        ts.exists(999)


def test_expired_in_store():
    def _test(ts: TrustStore):
        assert isinstance(
            ts.expired_in_store(context_type=context.SOURCE_ANDROID), bool
        )
        assert isinstance(
            ts.expired_in_store(context_type=context.SOURCE_CERTIFI), bool
        )
        assert isinstance(ts.expired_in_store(context_type=context.SOURCE_DART), bool)

    ts = TrustStore(authority_key_identifier=bad_ski)
    with pytest.raises(AttributeError):
        ts.expired_in_store(999)
    with pytest.raises(FileExistsError):
        ts.expired_in_store(context_type=context.SOURCE_CCADB)
    with pytest.raises(FileExistsError):
        ts.expired_in_store(context_type=context.SOURCE_JAVA)
    with pytest.raises(FileExistsError):
        ts.expired_in_store(context_type=context.SOURCE_CURL)
    with pytest.raises(FileExistsError):
        ts.expired_in_store(context_type=context.SOURCE_RUSSIA)
    with pytest.raises(FileExistsError):
        ts.expired_in_store(context_type=context.SOURCE_RUSTLS)
    _test(ts)


def test_no_args():
    with pytest.raises(TypeError):
        TrustStore()


def test_no_none_args():
    with pytest.raises(TypeError):
        TrustStore(None, None)


def test_key_identifier_type():
    with pytest.raises(TypeError):
        TrustStore(authority_key_identifier=False)


def test_check_bad_context():
    ts = TrustStore(authority_key_identifier=bad_ski)
    with pytest.raises(TypeError):
        ts.check_trust("None")
    assert isinstance(ts.check_trust(), bool)
    ts = TrustStore(authority_key_identifier=good_ski)
    with pytest.raises(AttributeError):
        ts.check_trust(99999)
    ts = TrustStore(authority_key_identifier=bad_ski)
    with pytest.raises(AttributeError):
        ts.check_trust(99999)


def test_trust_stores_from_chain():
    chain, _ = util.get_certificate_chain(host, 443)
    assert isinstance(trust_stores_from_chain(chain), list)
    with pytest.raises(util.InvalidChainError):
        trust_stores_from_chain(chain[1:])


def test_result():
    ts = TrustStore(authority_key_identifier=good_ski)
    assert isinstance(ts.to_dict(), dict)
    assert ts.ccadb
    assert ts.android
    assert ts.java
    assert ts.curl
    assert ts.certifi
    assert ts.dart
    assert ts.russia is False
    assert ts.rustls
    ts = TrustStore(authority_key_identifier=bad_ski)
    assert ts.ccadb is False
    assert ts.android is False
    assert ts.java is False
    assert ts.curl is False
    assert ts.certifi is False
    assert ts.dart is False
    assert ts.russia is False
    assert ts.rustls is False
