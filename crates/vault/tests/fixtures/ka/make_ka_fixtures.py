"""Generate the ka fixtures once: a KAM1 and a KAM2 vault with harmless values.

Run with the repository's Python (PyNaCl and key_amnesia installed), from
anywhere:

    HOME=$(mktemp -d) .venv/bin/python crates/vault/tests/fixtures/ka/make_ka_fixtures.py

The fixtures are committed; this script is kept so they can be regenerated if
ever needed and so a reader can see exactly how they were made. ka writes its
SENSITIVE KDF settings (Argon2id, t = 4, m = 1 GiB), so each fixture costs
about a second to open. The phrase and every value are made up.
"""

import shutil
import tempfile
from pathlib import Path

from key_amnesia import crypto, roles, vault

HERE = Path(__file__).resolve().parent
PHRASE = "correct horse"
VALUES = {
    "ALPHA": "fake-one",
    "BETA": "fake two lines\nx",
    "GAMMA": "fake-three",
}


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        kam1 = tmp / "kam1.bin"
        vault.save_vault(kam1, PHRASE, {"secrets": dict(VALUES)})
        shutil.copyfile(kam1, HERE / "kam1.bin")

        # KAM2: an admin (whose key the password opens) and a second member
        # who holds a wrap of one secret only.
        admin_sk, admin_pk = crypto.generate_box_keypair()
        sign_sk, sign_pk = crypto.generate_signing_keypair()
        _, bob_pk = crypto.generate_box_keypair()
        members = {
            admin_pk.hex(): {
                "name": "admin",
                "role": "admin",
                "box_pk": admin_pk.hex(),
                "added_at": "2026-01-01T00:00:00+00:00",
            },
            bob_pk.hex(): {
                "name": "bob",
                "role": "runner",
                "box_pk": bob_pk.hex(),
                "added_at": "2026-01-01T00:00:00+00:00",
            },
        }
        acl = {name: [admin_pk.hex()] for name in VALUES}
        acl["BETA"].append(bob_pk.hex())
        payload = {
            "secrets": dict(VALUES),
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
            "kam2": {
                "members": members,
                "acl": acl,
                "admin_signing_pk": sign_pk.hex(),
                "admin_signing_sk": sign_sk.hex(),
                "admin_box_sk": admin_sk.hex(),
                "admin_box_pk": admin_pk.hex(),
                "acl_signature": roles.sign_acl(sign_sk, members, acl),
            },
        }
        kam2 = tmp / "kam2.bin"
        vault.save_vault(kam2, PHRASE, payload)
        # Prove the fixtures read back with ka itself before committing them.
        assert vault.load_vault(kam1, PHRASE)["secrets"] == VALUES
        assert vault.load_vault(kam2, PHRASE)["secrets"] == VALUES
        shutil.copyfile(kam2, HERE / "kam2.bin")


if __name__ == "__main__":
    main()
