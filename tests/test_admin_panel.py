import tempfile
import unittest
import csv
from pathlib import Path

from admin_panel.core import Database, normalize_totp_secret, parse_import, totp_code
from admin_panel.integrations import normalize_country_catalog


class ImportTests(unittest.TestCase):
    def test_import_formats_and_country_aliases(self):
        accounts, errors = parse_import(
            "newTry[16] one@example.com:abc1\nTWO@example.com:def2,\u043c\u043e\u0437\u0430\u043c\u0431\u0438\u043a",
            "pl",
            "windows",
        )
        self.assertEqual(errors, [])
        self.assertEqual(accounts[0].profile_name, "newTry[16]")
        self.assertEqual(accounts[0].country, "pl")
        self.assertEqual(accounts[1].email, "two@example.com")
        self.assertEqual(accounts[1].country, "mz")

    def test_invalid_rows_are_reported(self):
        accounts, errors = parse_import("not-email\nvalid@example.com:1", "mz", "win")
        self.assertEqual(len(accounts), 1)
        self.assertEqual(errors[0]["line"], 1)

    def test_iproyal_country_catalog_is_normalized(self):
        catalog = normalize_country_catalog(
            {
                "countries": [
                    {"code": "MZ", "name": "Mozambique"},
                    {"code": "pl", "name": "Poland"},
                    {"code": "PL", "name": "Polska"},
                    {"code": "invalid", "name": "Ignored"},
                ]
            }
        )
        self.assertEqual(catalog, [{"code": "mz", "name": "Mozambique"}, {"code": "pl", "name": "Polska"}])


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.temp.name) / "test.sqlite3")

    def tearDown(self):
        self.temp.cleanup()

    def test_duplicate_email_is_skipped_and_names_increment(self):
        first, _ = parse_import("first@example.com:a1", "mz", "win")
        second, _ = parse_import("first@example.com:a1\nsecond@example.com:b2", "pl", "mac")
        self.assertEqual(self.db.import_accounts(first)["added"], 1)
        result = self.db.import_accounts(second)
        self.assertEqual(result["added"], 1)
        self.assertEqual(result["duplicates"], ["first@example.com"])
        rows = self.db.list_accounts()
        self.assertEqual([row["profile_name"] for row in rows], ["newTry[1]", "newTry[2]"])

    def test_authenticator_uses_rfc_totp_and_never_exposes_secret(self):
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        self.assertEqual(totp_code(secret, timestamp=59, digits=8), "94287082")
        self.assertEqual(
            normalize_totp_secret(f"otpauth://totp/Test?secret={secret}&issuer=Example"), secret
        )
        accounts, _ = parse_import("one@example.com:1", "mz", "win")
        self.db.import_accounts(accounts)
        account = self.db.set_authenticator(1, secret)
        self.assertTrue(account["has_authenticator"])
        self.assertNotIn("auth_secret", account)
        self.assertNotIn("auth_secret", self.db.list_accounts()[0])
        self.assertEqual(self.db.authenticator_codes(timestamp=59)[0]["code"], "287082")

    def test_job_requires_country_and_updates_selected_rows(self):
        accounts, _ = parse_import("one@example.com:1\ntwo@example.com:2", "", "win")
        self.db.import_accounts(accounts)
        with self.assertRaises(ValueError):
            self.db.create_job([1])
        job_id = self.db.create_job([1, 2], "mz", "mac")
        self.assertEqual(self.db.job(job_id)["total"], 2)
        rows = self.db.list_accounts()
        self.assertTrue(all(row["country"] == "mz" for row in rows))
        self.assertTrue(all(row["fingerprint_os"] == "mac" for row in rows))
        self.assertTrue(all(row["status"] == "queued" for row in rows))

    def test_worker_claims_one_job_and_marks_interrupted_work(self):
        accounts, _ = parse_import("one@example.com:1\ntwo@example.com:2", "mz", "win")
        self.db.import_accounts(accounts)
        first = self.db.create_job([1])
        second = self.db.create_job([2])
        self.assertEqual(self.db.claim_next_job(), first)
        self.assertEqual(self.db.job(first)["status"], "running")
        self.assertEqual(self.db.job(second)["status"], "queued")
        self.assertEqual(self.db.fail_interrupted_jobs(), 1)
        self.assertEqual(self.db.job(first)["status"], "interrupted")
        self.assertEqual(self.db.claim_next_job(), second)

    def test_account_cannot_be_queued_twice(self):
        accounts, _ = parse_import("one@example.com:1", "mz", "win")
        self.db.import_accounts(accounts)
        self.db.create_job([1])
        with self.assertRaisesRegex(ValueError, "active job"):
            self.db.create_job([1])

    def test_proxy_change_can_update_country_and_endpoint(self):
        accounts, _ = parse_import("one@example.com:1", "mz", "win")
        self.db.import_accounts(accounts)
        self.db.mark_synced(1, exists=True, profile_id="profile-id")
        self.assertTrue(self.db.begin_proxy_rotation(1))
        self.assertFalse(self.db.begin_proxy_rotation(1))
        self.db.mark_proxy_changed(1, "proxy-id", "socks5://user@host:123", "pl")
        account = self.db.account(1)
        self.assertEqual(account["country"], "pl")
        self.assertEqual(account["proxy_endpoint"], "socks5://user@host:123")

    def test_fraud_score_is_saved_and_cleared_when_proxy_changes(self):
        accounts, _ = parse_import("one@example.com:1", "mz", "win")
        self.db.import_accounts(accounts)
        self.db.mark_synced(1, exists=True, profile_id="profile-id", proxy_id="proxy-id")
        checked = self.db.mark_fraud_checked(1, 27, "8.8.8.8", "low")
        self.assertEqual(checked["fraud_score"], 27)
        self.assertEqual(checked["fraud_ip"], "8.8.8.8")

        self.assertTrue(self.db.begin_proxy_rotation(1))
        self.db.mark_proxy_changed(1, "new-proxy", "socks5://user@new-host:123")
        changed = self.db.account(1)
        self.assertEqual(changed["fraud_score"], -1)
        self.assertEqual(changed["fraud_ip"], "")

    def test_sync_does_not_overwrite_an_active_account(self):
        accounts, _ = parse_import("one@example.com:1", "mz", "win")
        self.db.import_accounts(accounts)
        self.db.create_job([1])
        updated = self.db.mark_synced(1, exists=False)
        self.assertFalse(updated)
        self.assertEqual(self.db.account(1)["status"], "queued")

    def test_edit_marks_created_profile_for_sync_and_delete_removes_it(self):
        accounts, _ = parse_import("one@example.com:Code1", "mz", "win")
        self.db.import_accounts(accounts)
        self.db.mark_synced(1, exists=True, profile_id="profile-id")
        updated = self.db.update_account(
            1,
            {"profile_name": "campaign-1", "email": "changed@example.com", "code": "New2"},
        )
        self.assertEqual(updated["status"], "pending_sync")
        self.assertEqual(updated["profile_name"], "campaign-1")
        self.assertTrue(
            self.db.mark_synced(
                1,
                exists=True,
                profile_id="profile-id",
                preserve_pending=True,
            )
        )
        self.assertEqual(self.db.account(1)["status"], "pending_sync")
        self.assertEqual(self.db.begin_account_delete(1), "pending_sync")
        self.assertTrue(self.db.delete_account(1, "pending_sync"))
        self.assertIsNone(self.db.account(1))
        self.assertEqual(len(self.db.trashed_accounts()), 1)

    def test_saving_unchanged_created_profile_does_not_require_sync(self):
        accounts, _ = parse_import("one@example.com:Code1", "mz", "win")
        self.db.import_accounts(accounts)
        self.db.mark_synced(1, exists=True, profile_id="profile-id")
        account = self.db.account(1)

        updated = self.db.update_account(
            1,
            {
                "profile_name": account["profile_name"],
                "email": account["email"],
                "code": account["code"],
                "country": account["country"],
            },
        )

        self.assertEqual(updated["status"], "created")

    def test_trashed_account_can_be_restored_with_vision_link(self):
        accounts, _ = parse_import("one@example.com:Code1", "mz", "win")
        self.db.import_accounts(accounts)
        self.db.mark_synced(1, exists=True, profile_id="profile-id", proxy_id="proxy-id")
        self.assertEqual(self.db.begin_account_delete(1), "created")
        self.assertTrue(self.db.delete_account(1, "created"))

        trash_id = self.db.trashed_accounts()[0]["trash_id"]
        restored = self.db.restore_account(trash_id)

        self.assertIsNotNone(restored)
        self.assertEqual(restored["status"], "created")
        self.assertEqual(restored["vision_profile_id"], "profile-id")
        self.assertEqual(self.db.trashed_accounts(), [])

    def test_trashed_account_deleted_from_vision_restores_as_not_created(self):
        accounts, _ = parse_import("one@example.com:Code1", "mz", "win")
        self.db.import_accounts(accounts)
        self.db.mark_synced(1, exists=True, profile_id="profile-id", proxy_id="proxy-id")
        self.assertEqual(self.db.begin_account_delete(1), "created")
        self.assertTrue(self.db.delete_account(1, "created", clear_vision=True))

        trash_id = self.db.trashed_accounts()[0]["trash_id"]
        restored = self.db.restore_account(trash_id)

        self.assertEqual(restored["status"], "not_created")
        self.assertEqual(restored["vision_profile_id"], "")
        self.assertEqual(restored["vision_proxy_id"], "")

    def test_uncreated_account_can_be_permanently_deleted_without_trash(self):
        accounts, _ = parse_import("one@example.com:Code1", "mz", "win")
        self.db.import_accounts(accounts)

        self.assertTrue(self.db.permanently_delete_uncreated_account(1))

        self.assertIsNone(self.db.account(1))
        self.assertEqual(self.db.trashed_accounts(), [])

    def test_created_account_cannot_be_permanently_deleted(self):
        accounts, _ = parse_import("one@example.com:Code1", "mz", "win")
        self.db.import_accounts(accounts)
        self.db.mark_synced(1, exists=True, profile_id="profile-id")

        with self.assertRaisesRegex(ValueError, "Created Vision profiles"):
            self.db.permanently_delete_uncreated_account(1)

        self.assertIsNotNone(self.db.account(1))

    def test_vision_delete_keeps_account_and_clears_remote_details(self):
        accounts, _ = parse_import("one@example.com:Code1", "mz", "win")
        self.db.import_accounts(accounts)
        self.db.mark_synced(
            1,
            exists=True,
            profile_id="profile-id",
            proxy_id="proxy-id",
            proxy_endpoint="socks5://user@host:123",
        )

        self.assertEqual(self.db.begin_account_delete(1), "created")
        self.assertTrue(self.db.mark_vision_deleted(1))

        account = self.db.account(1)
        self.assertIsNotNone(account)
        self.assertEqual(account["status"], "not_created")
        self.assertEqual(account["vision_profile_id"], "")
        self.assertEqual(account["vision_proxy_id"], "")
        self.assertEqual(account["proxy_endpoint"], "")

    def test_proxy_csv_enriches_country_and_os(self):
        accounts, _ = parse_import("newTry[8] eight@example.com:8", "", "win")
        self.db.import_accounts(accounts)
        csv_path = Path(self.temp.name) / "proxies.csv"
        with csv_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=["title", "proxy_password", "fingerprint_os"])
            writer.writeheader()
            writer.writerow(
                {
                    "title": "newTry[8]",
                    "proxy_password": "secret_country-mz_session-123_lifetime-168h",
                    "fingerprint_os": "mac",
                }
            )
        self.assertEqual(self.db.enrich_from_proxy_csv(csv_path), 1)
        row = self.db.list_accounts()[0]
        self.assertEqual(row["country"], "mz")
        self.assertEqual(row["fingerprint_os"], "mac")

    def test_codes_are_optional_through_50_and_generated_after_50(self):
        accounts, errors = parse_import(
            "newTry[50] fifty@example.com\nnewTry[51] fiftyone@example.com",
            "mz",
            "win",
        )
        self.assertEqual(errors, [])
        self.db.import_accounts(accounts)
        rows = self.db.list_accounts()
        self.assertEqual(rows[0]["code"], "")
        self.assertEqual(len(rows[1]["code"]), 10)
        self.assertTrue(rows[1]["code"].isalnum())
        self.assertTrue(any(character.isdigit() for character in rows[1]["code"]))

    def test_clearing_code_after_50_generates_a_replacement(self):
        accounts, _ = parse_import("newTry[51] account@example.com:Manual1", "mz", "win")
        self.db.import_accounts(accounts)
        updated = self.db.update_account(1, {"code": ""})
        self.assertIsNotNone(updated)
        self.assertEqual(len(updated["code"]), 10)
        self.assertTrue(any(character.isdigit() for character in updated["code"]))


if __name__ == "__main__":
    unittest.main()
