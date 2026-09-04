"""Ragger fixtures for the pinned Speculos device test."""

from ragger.conftest import configuration


# Public development-only mnemonic. Never use it for funds. Pinning it makes
# the exact public-key and signature vectors independent of Ragger defaults.
configuration.OPTIONAL.CUSTOM_SEED = (
    "glory promote mansion idle axis finger extra february uncover one trip "
    "resource lawn turtle enact monster seven myth punch hobby comfort wild "
    "raise skin"
)
configuration.OPTIONAL.BACKEND_SCOPE = "function"

pytest_plugins = ("ragger.conftest.base_conftest",)
