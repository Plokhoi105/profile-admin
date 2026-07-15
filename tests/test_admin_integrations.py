import tempfile
import unittest
import urllib.error
from io import BytesIO
from pathlib import Path
from unittest.mock import Mock, patch

from admin_panel.integrations import (
    ProfileCreator,
    ProxySelectionError,
    VisionApiError,
    parse_scamalytics_response,
    request_json,
)


class IPRoyalIntegrationTests(unittest.TestCase):
    def test_vision_http_error_keeps_api_validation_message(self):
        response = BytesIO(b'{"message":"fingerprint.media_devices is invalid"}')
        error = urllib.error.HTTPError("https://vision.test", 400, "Bad Request", {}, response)

        with patch("admin_panel.integrations.urllib.request.urlopen", side_effect=error):
            with self.assertRaisesRegex(VisionApiError, "fingerprint.media_devices is invalid"):
                request_json("POST", "https://vision.test", "test-token", {"profile_name": "test"})

    def test_scamalytics_response_is_normalized(self):
        result = parse_scamalytics_response(
            {
                "scamalytics": {
                    "status": "ok",
                    "ip": "216.58.194.174",
                    "scamalytics_score": 42,
                    "scamalytics_risk": "medium",
                }
            },
            "216.58.194.174",
        )
        self.assertEqual(result, {"ip": "216.58.194.174", "score": 42, "risk": "medium"})

    def test_proxy_fraud_check_uses_vision_credentials_without_returning_them(self):
        with tempfile.TemporaryDirectory() as directory:
            creator = ProfileCreator(Path(directory))
        creator.scamalytics_user = "test-user"
        creator.scamalytics_key = "secret-key"
        creator.get_vision_proxy = Mock(
            return_value={
                "proxy_ip": "proxy.example",
                "proxy_port": 1080,
                "proxy_username": "login",
                "proxy_password": "proxy-secret",
            }
        )
        with (
            patch("admin_panel.integrations.resolve_proxy_exit_ip", return_value="8.8.8.8") as resolve,
            patch(
                "admin_panel.integrations.scamalytics_lookup",
                return_value={"ip": "8.8.8.8", "score": 3, "risk": "low"},
            ) as lookup,
        ):
            result = creator.check_proxy_fraud({"vision_proxy_id": "proxy-id"})

        self.assertEqual(result, {"ip": "8.8.8.8", "score": 3, "risk": "low"})
        self.assertEqual(resolve.call_args.args[0]["password"], "proxy-secret")
        lookup.assert_called_once_with("test-user", "secret-key", "8.8.8.8")

    def test_fingerprint_uses_noise_and_expected_media_device_ranges(self):
        with tempfile.TemporaryDirectory() as directory:
            creator = ProfileCreator(Path(directory))
        response = {
            "data": {
                "fingerprint": {
                    "navigator": {"platform": "Win32"},
                    "canvas_pref": "real",
                    "media_devices": {"audio_input": 4, "audio_output": 4, "video_input": 4},
                }
            }
        }

        with patch("admin_panel.integrations.request_json", return_value=response):
            platform, fingerprint = creator.fingerprint("win")

        self.assertEqual(platform, "Windows")
        self.assertEqual(fingerprint["canvas_pref"], {"noise": 1.0})
        self.assertEqual(fingerprint["webgl_pref"], {"noise": 1.0})
        self.assertEqual(fingerprint["audio_pref"], 1)
        self.assertEqual(fingerprint["media_devices"]["audio_input"], 1)
        self.assertIn(fingerprint["media_devices"]["audio_output"], {1, 2})
        self.assertIn(fingerprint["media_devices"]["video_input"], {0, 1})
        self.assertEqual(fingerprint["navigator"]["language"], "auto")
        self.assertEqual(fingerprint["navigator"]["languages"], [])

    def test_generate_proxies_uses_direct_api(self):
        with tempfile.TemporaryDirectory() as directory:
            creator = ProfileCreator(Path(directory))
        creator.vision_token = "vision-test"
        creator.folder_id = "folder-test"
        creator.iproyal_token = "iproyal-test"
        creator.subuser = "team_secret_k2"
        responses = [
            {"data": [{"hash": "subuser-hash", "username": "Team_Secret_k2"}]},
            {"proxy_list": "geo.iproyal.com:32325:user:pass-one\ngeo.iproyal.com:32325:user:pass-two"},
        ]
        with patch("admin_panel.integrations.iproyal_request_json", side_effect=responses) as request:
            proxies = creator.generate_proxies("mz", 2)
        self.assertEqual(len(proxies), 2)
        self.assertEqual(proxies[0]["host"], "geo.iproyal.com")
        self.assertEqual(proxies[1]["password"], "pass-two")
        payload = request.call_args_list[1].args[4]
        self.assertEqual(payload["location"], "_country-mz")
        self.assertEqual(payload["proxy_count"], 2)

    def test_full_proxy_endpoint_includes_encoded_credentials_only_on_demand(self):
        proxy = {
            "proxy_type": "SOCKS5",
            "proxy_ip": "example.proxy",
            "proxy_port": 1080,
            "proxy_username": "user@email",
            "proxy_password": "p:ss word",
        }

        self.assertEqual(
            ProfileCreator.proxy_endpoint(proxy),
            "socks5://user@email@example.proxy:1080",
        )
        self.assertEqual(
            ProfileCreator.full_proxy_endpoint(proxy),
            "socks5://user%40email:p%3Ass%20word@example.proxy:1080",
        )

    def test_profile_name_contains_country_and_rotation_assigns_proxy(self):
        with tempfile.TemporaryDirectory() as directory:
            creator = ProfileCreator(Path(directory))
        account = {
            "profile_name": "newTry[1]",
            "country": "mz",
            "vision_profile_id": "profile-id",
            "email": "one@example.com",
            "code": "Code1",
        }
        creator.get_vision_profile = Mock(return_value={"id": "profile-id"})
        proxy = {"host": "geo.iproyal.com", "port": 123, "login": "user", "password": "secret"}
        creator.select_low_fraud_proxy = Mock(
            return_value={"proxy": proxy, "fraud": {"score": 12, "ip": "8.8.8.8", "risk": "low"}, "attempts": 1}
        )
        creator.create_vision_proxy = Mock(return_value="proxy-id")
        creator.update_vision_profile = Mock(return_value={"id": "profile-id"})

        result = creator.rotate_proxy(account)

        self.assertEqual(creator.display_profile_name(account), "newTry[1] Mozambique")
        self.assertEqual(result["proxy_endpoint"], "socks5://user@geo.iproyal.com:123")
        self.assertEqual(result["fraud"]["score"], 12)
        creator.update_vision_profile.assert_called_once_with(
            "profile-id",
            {
                "proxy_id": {"id": "proxy-id"},
                "profile_name": "newTry[1] Mozambique",
                "profile_notes": "one@example.com:Code1",
            },
        )

    def test_proxy_selection_retries_until_score_is_below_25(self):
        with tempfile.TemporaryDirectory() as directory:
            creator = ProfileCreator(Path(directory))
        creator.scamalytics_user = "user"
        creator.scamalytics_key = "key"
        first = {"host": "one", "port": 1, "login": "u", "password": "p"}
        second = {"host": "two", "port": 2, "login": "u", "password": "p"}
        creator.generate_proxies = Mock(side_effect=[[first], [second]])
        creator.check_candidate_proxy = Mock(
            side_effect=[
                {"score": 80, "ip": "1.1.1.1", "risk": "high"},
                {"score": 24, "ip": "2.2.2.2", "risk": "low"},
            ]
        )
        creator.confirm_candidate_proxy = Mock()

        selected = creator.select_low_fraud_proxy("mz")

        self.assertIs(selected["proxy"], second)
        self.assertEqual(selected["fraud"]["score"], 24)
        self.assertEqual(selected["attempts"], 2)
        self.assertEqual(creator.generate_proxies.call_count, 2)
        creator.confirm_candidate_proxy.assert_called_once_with(second, "2.2.2.2")

    def test_proxy_stability_check_retries_once_without_second_fraud_lookup(self):
        with tempfile.TemporaryDirectory() as directory:
            creator = ProfileCreator(Path(directory))
        proxy = {"host": "proxy", "port": 1, "login": "u", "password": "p"}

        with patch(
            "admin_panel.integrations.resolve_proxy_exit_ip",
            side_effect=[TimeoutError("slow proxy"), "2.2.2.2"],
        ) as resolve_ip, patch("admin_panel.integrations.time.sleep") as sleep:
            creator.confirm_candidate_proxy(proxy, "2.2.2.2")

        self.assertEqual(resolve_ip.call_count, 2)
        sleep.assert_called_once_with(1)

    def test_proxy_selection_warns_after_five_high_scores(self):
        with tempfile.TemporaryDirectory() as directory:
            creator = ProfileCreator(Path(directory))
        creator.scamalytics_user = "user"
        creator.scamalytics_key = "key"
        proxy = {"host": "proxy", "port": 1, "login": "u", "password": "p"}
        creator.generate_proxies = Mock(return_value=[proxy])
        creator.check_candidate_proxy = Mock(
            side_effect=[{"score": score, "ip": "1.1.1.1", "risk": "high"} for score in (25, 40, 55, 70, 90)]
        )

        with self.assertRaisesRegex(ProxySelectionError, "5 прокси подряд"):
            creator.select_low_fraud_proxy("mz")

        self.assertEqual(creator.generate_proxies.call_count, 5)

    def test_sync_renames_profile_and_resolves_current_proxy_without_password(self):
        with tempfile.TemporaryDirectory() as directory:
            creator = ProfileCreator(Path(directory))
        account = {
            "profile_name": "newTry[2]",
            "country": "pl",
            "vision_profile_id": "profile-id",
            "email": "two@example.com",
            "code": "Code2",
        }
        profile = {"id": "profile-id", "profile_name": "newTry[2]", "proxy_id": "proxy-id"}
        creator.get_vision_profile = Mock(return_value=profile)
        creator.update_vision_profile = Mock(return_value={**profile, "profile_name": "newTry[2] Poland"})
        creator.get_vision_proxy = Mock(
            return_value={
                "id": "proxy-id",
                "proxy_type": "SOCKS5",
                "proxy_ip": "example.proxy",
                "proxy_port": 1080,
                "proxy_username": "login",
                "proxy_password": "must-not-leak",
            }
        )

        result = creator.sync_account(account, push_changes=True)

        self.assertTrue(result["exists"])
        self.assertEqual(result["proxy_endpoint"], "socks5://login@example.proxy:1080")
        self.assertNotIn("must-not-leak", result["proxy_endpoint"])
        creator.update_vision_profile.assert_called_once_with(
            "profile-id",
            {"profile_name": "newTry[2] Poland", "profile_notes": "two@example.com:Code2"},
        )


if __name__ == "__main__":
    unittest.main()
