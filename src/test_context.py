from tlstrust import TrustStore
from tlstrust import context

GOOD_SKI = "bf5fb7d1cedd1f86f45b55acdcd710c20ea988e7"


def test_setup():
    store = TrustStore(authority_key_identifier=GOOD_SKI)
    assert isinstance(store, TrustStore)
    assert isinstance(store.is_trusted, bool)


def test_context_stores():
    store = TrustStore(authority_key_identifier=GOOD_SKI)
    for _, ctx in context.STORES.items():
        assert isinstance(store.check_trust(ctx), bool)


def test_context_sources():
    store = TrustStore(authority_key_identifier=GOOD_SKI)
    for _, ctx in context.SOURCES.items():
        assert isinstance(store.check_trust(ctx), bool)


def test_context_platforms():
    store = TrustStore(authority_key_identifier=GOOD_SKI)
    for _, ctx in context.PLATFORMS.items():
        assert isinstance(store.check_trust(ctx), bool)


def test_context_browsers():
    store = TrustStore(authority_key_identifier=GOOD_SKI)
    for _, ctx in context.BROWSERS.items():
        assert isinstance(store.check_trust(ctx), bool)


def test_context_languages():
    store = TrustStore(authority_key_identifier=GOOD_SKI)
    for _, ctx in context.LANGUAGES.items():
        assert isinstance(store.check_trust(ctx), bool)
