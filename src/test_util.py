import pytest
from OpenSSL.crypto import X509
from cryptography.x509.extensions import SubjectKeyIdentifier
from tlstrust import util
from tlstrust import context

good_ski = 'bf5fb7d1cedd1f86f45b55acdcd710c20ea988e7'
bad_ski = 'c4a7b1a47b2c71fadbe14b9075ffc41560858910'
host = 'ssllabs.com'

def test_cert_retrieval():
    assert isinstance(util.get_certificate_from_store(good_ski, context_type=context.SOURCE_CCADB), X509)
    with pytest.raises(FileExistsError):
        util.get_certificate_from_store(bad_ski, context_type=context.SOURCE_RUSSIA)
    with pytest.raises(AttributeError):
        util.get_certificate_from_store(bad_ski, 999)

def test_valid_context_type():
    assert util.valid_context_type(context.SOURCE_CCADB)
    assert not util.valid_context_type(999)

def test_get_key_identifier_hex():
    cert = util.get_certificate_from_store(good_ski, context_type=context.SOURCE_CCADB)
    assert good_ski == util.get_key_identifier_hex(cert.to_cryptography(), extention=SubjectKeyIdentifier, key='digest')

def test_match_certificate():
    cert = util.get_certificate_from_store(good_ski, context_type=context.SOURCE_CCADB)
    assert util.match_certificate(good_ski, cert)

def test_get_certificate_chain():
    cert = util.get_certificate_from_store(good_ski, context_type=context.SOURCE_CCADB)
    chain, peer = util.get_certificate_chain(host, 443, client_cert=cert)
    assert isinstance(chain, list)
    assert isinstance(peer, str)
    with pytest.raises(TypeError):
        util.get_certificate_chain(host, None)
    with pytest.raises(ValueError):
        util.get_certificate_chain(None, 443)

def test_get_leaf():
    chain, _ = util.get_certificate_chain(host, 443)
    assert isinstance(util.get_leaf(chain), X509)

def test_build_chains():
    chain, _ = util.get_certificate_chain(host, 443)
    leaf = util.get_leaf(chain)
    assert isinstance(util.build_chains(leaf, chain), dict)
