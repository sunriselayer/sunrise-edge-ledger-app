"""End-to-end tests against the real Nano S+ binary under Speculos."""

from contextlib import contextmanager
from pathlib import Path
from typing import Generator

import pytest
from ragger.backend.interface import BackendInterface, RAPDU
from ragger.bip import pack_derivation_path
from ragger.error import ExceptionRAPDU


CLA = 0xE0
INS_GET_CONFIGURATION = 0x00
INS_VERIFY_PUBLIC_KEY = 0x02
INS_SIGN_TRANSACTION = 0x04
P1_FIRST = 0x00
P1_CONTINUE = 0x01
P1_LAST = 0x02
MAX_FRAME_CHUNK = 230
PATH = "m/44'/21333'/0'/0'/0'"
SNAPSHOT_PATH = Path("/tmp/sunrise-ragger-artifacts")

# The public development-only seed pinned in conftest.py derives this key at
# PATH via SLIP-0010 Ed25519. These constants were independently computed and
# pin the device derivation and signing results, not only validity.
EXPECTED_PUBLIC_KEY = bytes.fromhex(
    "df8608651a39745d3ae6eb2d4378619f"
    "d033c24eee6962c97b21750ce0fd88fb"
)
EXPECTED_SIGNATURE = bytes.fromhex(
    "94417335ee3f6dc33a9e0eb96785c159"
    "b6fe5749aa21f55a51d1c406413f16a9"
    "0722a8cbe04a9069f3c4d94d24b187ec"
    "77aea4a270adc3eb11424e5bdcee8b01"
)
EXPECTED_CONFIGURATION = bytes.fromhex("000100010000")


def source_fixture() -> bytes:
    fixture = Path(
        "crates/sunrise-edge-ledger-core/tests/fixtures/recognized_transfer.hex"
    )
    return bytes.fromhex(fixture.read_text(encoding="ascii").strip())


def device_fixture() -> bytes:
    source = source_fixture()
    old_sender = bytes([1]) * 32
    assert source.count(old_sender) == 1
    return source.replace(old_sender, EXPECTED_PUBLIC_KEY, 1)


def send_sign_prefix(backend: BackendInterface, frame: bytes) -> bytes:
    path = pack_derivation_path(PATH)
    chunks = [
        frame[offset : offset + MAX_FRAME_CHUNK]
        for offset in range(0, len(frame), MAX_FRAME_CHUNK)
    ]
    assert len(chunks) >= 2
    first_data = len(frame).to_bytes(4, "big") + path + chunks[0]
    assert len(first_data) == 255
    first = backend.exchange(
        cla=CLA,
        ins=INS_SIGN_TRANSACTION,
        p1=P1_FIRST,
        p2=0,
        data=first_data,
    )
    assert first.data == b""

    for chunk in chunks[1:-1]:
        continued = backend.exchange(
            cla=CLA,
            ins=INS_SIGN_TRANSACTION,
            p1=P1_CONTINUE,
            p2=0,
            data=chunk,
        )
        assert continued.data == b""
    return chunks[-1]


@contextmanager
def sign_last_async(
    backend: BackendInterface, frame: bytes
) -> Generator[None, None, None]:
    last = send_sign_prefix(backend, frame)
    with backend.exchange_async(
        cla=CLA,
        ins=INS_SIGN_TRANSACTION,
        p1=P1_LAST,
        p2=0,
        data=last,
    ):
        yield


def test_configuration_and_exact_slip10_public_key(backend, scenario_navigator):
    configuration = backend.exchange(
        cla=CLA, ins=INS_GET_CONFIGURATION, p1=0, p2=0, data=b""
    )
    assert configuration.data == EXPECTED_CONFIGURATION

    with backend.exchange_async(
        cla=CLA,
        ins=INS_VERIFY_PUBLIC_KEY,
        p1=1,
        p2=0,
        data=pack_derivation_path(PATH),
    ):
        scenario_navigator.address_review_approve(
            path=SNAPSHOT_PATH, do_comparison=False
        )

    response = backend.last_async_response
    assert isinstance(response, RAPDU)
    assert response.data == EXPECTED_PUBLIC_KEY


def test_exact_frame_signing_vector(backend, scenario_navigator):
    frame = device_fixture()
    with sign_last_async(backend, frame):
        scenario_navigator.review_approve(path=SNAPSHOT_PATH, do_comparison=False)

    response = backend.last_async_response
    assert isinstance(response, RAPDU)
    assert response.data == EXPECTED_SIGNATURE


def test_sender_mismatch_fails_before_review(backend):
    frame = source_fixture()
    last = send_sign_prefix(backend, frame)
    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange(
            cla=CLA,
            ins=INS_SIGN_TRANSACTION,
            p1=P1_LAST,
            p2=0,
            data=last,
        )
    assert error.value.status == 0x6A80
    assert error.value.data == b""


def test_failed_and_reset_sessions_do_not_poison_next_signing(
    backend, scenario_navigator
):
    mismatched_last = send_sign_prefix(backend, source_fixture())
    with pytest.raises(ExceptionRAPDU) as mismatch:
        backend.exchange(
            cla=CLA,
            ins=INS_SIGN_TRANSACTION,
            p1=P1_LAST,
            p2=0,
            data=mismatched_last,
        )
    assert mismatch.value.status == 0x6A80

    reset_frame = device_fixture()
    send_sign_prefix(backend, reset_frame)
    reset = backend.exchange(cla=CLA, ins=0x06, p1=0, p2=0, data=b"")
    assert reset.data == b""

    with sign_last_async(backend, device_fixture()):
        scenario_navigator.review_approve(
            path=SNAPSHOT_PATH, do_comparison=False
        )
    response = backend.last_async_response
    assert isinstance(response, RAPDU)
    assert response.data == EXPECTED_SIGNATURE


def test_user_rejection_returns_deny(backend, scenario_navigator):
    with pytest.raises(ExceptionRAPDU) as error:
        with sign_last_async(backend, device_fixture()):
            scenario_navigator.review_reject(
                path=SNAPSHOT_PATH, do_comparison=False
            )
    assert error.value.status == 0x6985
    assert error.value.data == b""
