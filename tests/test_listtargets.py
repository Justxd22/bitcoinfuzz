from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "tools" / "listtargets.py"

SPEC = importlib.util.spec_from_file_location("listtargets", SCRIPT_PATH)
assert SPEC is not None
assert SPEC.loader is not None
listtargets = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(listtargets)

EXPECTED_TARGETS = [
    "script",
    "deserialize_block",
    "script_eval",
    "verify_script",
    "descriptor_parse",
    "miniscript_parse",
    "deserialize_invoice",
    "address_parse",
    "psbt_parse",
    "addrv2",
    "deserialize_offer",
    "cmpctblocks_parse",
    "parse_p2p_message",
    "parse_p2p_lightning_message",
    "transaction_eval",
    "bip32_master_keygen",
    "kernel_block",
    "kernel_transaction",
    "private_to_public_key",
    "sign_compact",
    "sign_der",
    "sign_verify",
    "ecdh",
    "sign_schnorr",
    "bip32_deserialize_extended_key",
    "decode_ellswift",
    "schnorr_verify",
    "decode_onion",
    "stump_modify_add",
    "bip32_derive_from_path",
]


def test_extracts_all_known_targets_from_driver_cpp() -> None:
    assert listtargets.extract_targets(REPO_ROOT / "driver.cpp") == EXPECTED_TARGETS


def test_cli_outputs_json() -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            "--format=json",
            "--driver",
            str(REPO_ROOT / "driver.cpp"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert json.loads(result.stdout) == EXPECTED_TARGETS
    assert result.stderr == ""


def test_parser_ignores_comments_and_allows_flexible_whitespace(tmp_path: Path) -> None:
    driver_path = tmp_path / "driver.cpp"
    driver_path.write_text(
        textwrap.dedent("""
            void Driver::Run(const uint8_t *data, const size_t size,
                             const std::string &target) const {
              // if (target == "commented_line") {
              if(target=="first") {
                this->FirstTarget(buffer);
              } else if (
                target
                ==
                "second"
              ) {
                this->SecondTarget(buffer);
              }
              /*
              } else if (target == "commented_block") {
                this->CommentedBlockTarget(buffer);
              }
              */
              else {
                assert(false);
              }
            };
            """),
        encoding="utf-8",
    )

    assert listtargets.extract_targets(driver_path) == ["first", "second"]
