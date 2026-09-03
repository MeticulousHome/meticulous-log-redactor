import json
import os
import resource
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock

from log_redactor import RedactionCancelled, load_key, redact

TEST_KEY = bytes(range(32))


class LogRedactorTests(unittest.TestCase):
    def redact(self, text):
        return redact(text, TEST_KEY)[0]

    def test_must_redact_vectors(self):
        text = "\n".join(
            [
                "Config: added 'ssid' value 'HomeNet'",
                "wlan0: Trying to associate with SSID 'HomeNet'",
                'Connected to wireless network "HomeNet"',
                (
                    "SME: Trying to authenticate with aa:bb:cc:dd:ee:ff "
                    "(SSID='HomeNet' freq=2437 MHz)"
                ),
                "policy: set 'HomeNet' (wlan0) as default",
                "selected access point 'HomeNet'",
                "Activation: starting connection 'HomeNet'",
                "ssid: HomeNet",
                ("set-hw-addr: set MAC address to AA:BB:CC:DD:EE:FF " "(scanning)"),
                ("Registering new address record for " "fe80::1122:3344:5566:7788 on wlan0.*."),
                "CONF:   root_password: s3cr3tvalue",
                "CONF:   APPassword: '123456789012'",
                '{"root_password": "abc123", "serial": "332233"}',
                "user renamed network to HomeNet today",
                "systemd-timedated - Changed time zone to 'America/Mexico_City' (CST).",
                "timezone_manager INFO new system time zone: Europe/Berlin",
                "Time zone: America/Argentina/Buenos_Aires (ART, -0300)",
                "Etc/GMT-6 carries an offset",
            ]
        )

        output = self.redact(text)

        for sensitive in (
            "HomeNet",
            "aa:bb:cc:dd:ee:ff",
            "AA:BB:CC:DD:EE:FF",
            "fe80::1122:3344:5566:7788",
            "s3cr3tvalue",
            "123456789012",
            "abc123",
            "Mexico_City",
            "Berlin",
            "Buenos_Aires",
            "Argentina",
            # The trailing parenthetical is the leak the zone rule would
            # otherwise leave behind: CST pins UTC-6, ART pins UTC-3.
            "(CST)",
            "ART",
            "-0300",
            "GMT-6",
        ):
            self.assertNotIn(sensitive, output)
        self.assertIn("root_password: [REDACTED]", output)
        self.assertIn("APPassword: '[REDACTED]'", output)
        self.assertIn('"root_password": "[REDACTED]"', output)
        self.assertRegex(output, r"SSID='\[SSID_[0-9a-f]{8}\]'")
        self.assertRegex(output, r"with \[MAC_[0-9a-f]{8}\]")
        self.assertRegex(output, r"for \[IPV6_[0-9a-f]{8}\]")
        # The area survives: a continent identifies nobody, and it keeps enough
        # signal to tell a DST bug from a clock-never-synced bug.
        self.assertIn("to 'America/*****' (*****).", output)
        self.assertIn("new system time zone: Europe/*****", output)
        self.assertIn("Time zone: America/***** (*****)", output)
        self.assertIn("Etc/***** carries an offset", output)

    def test_network_manager_credential_form_is_redacted(self):
        output = self.redact("Config: added 'psk' value '<hidden>'")
        self.assertEqual(output, "Config: added 'psk' value '[REDACTED]'")

    def test_pairing_code_and_bearer_tokens_are_redacted(self):
        text = "\n".join(
            [
                "pairing code: 482913",
                "Authorization: Bearer abcDEF-123_xyz987",
                "request header Bearer abcDEF-123_xyz987",
                "bearer_token=abcDEF-123_xyz987",
            ]
        )

        output = self.redact(text)

        self.assertNotIn("482913", output)
        self.assertNotIn("abcDEF-123_xyz987", output)
        self.assertEqual(
            output,
            "\n".join(
                [
                    "pairing code: [REDACTED]",
                    "Authorization: [REDACTED]",
                    "request header Bearer [REDACTED]",
                    "bearer_token=[REDACTED]",
                ]
            ),
        )

    def test_credentials_run_before_identifier_rules(self):
        output = self.redact("password: aa:bb:cc:dd:ee:ff")
        self.assertEqual(output, "password: [REDACTED]")

    def test_known_wifis_keys_are_redacted_and_attributes_are_not_ssids(self):
        text = (
            "config DEBUG CONF:   wifi:\r\n"
            "config DEBUG CONF:     KnownWifis:\r\n"
            "config DEBUG CONF:       Some Network 5G:\r\n"
            "config DEBUG CONF:         password: example-pass\r\n"
            "config DEBUG CONF:         last_used: yesterday"
        )

        output = self.redact(text)

        self.assertNotIn("Some Network 5G", output)
        self.assertRegex(
            output,
            r"CONF:       \[SSID_[0-9a-f]{8}\]:\r\n",
        )
        self.assertIn("password: [REDACTED]", output)
        self.assertIn("last_used: yesterday", output)
        self.assertFalse(output.endswith(("\n", "\r")))
        self.assertEqual(self.redact(output), output)

    def test_leading_compressed_ipv6_is_redacted(self):
        output = self.redact("peer ::abcd:1234 connected; loopback ::1; unspecified ::")

        self.assertNotIn("::abcd:1234", output)
        self.assertRegex(output, r"peer \[IPV6_[0-9a-f]{8}\] connected")
        self.assertIn("loopback ::1", output)
        self.assertIn("unspecified ::", output)

    def test_allowlisted_addresses_are_unchanged(self):
        text = (
            "ff:ff:ff:ff:ff:ff 00:00:00:00:00:00 " "33:33:00:00:00:01 01:00:5e:00:00:fb ::1 ::"
        )
        self.assertEqual(self.redact(text), text)

    def test_diagnostic_preservation_vectors(self):
        vectors = [
            "Firmware: BCM4339/2 version 6.37.39.141 (73212ff CY)",
            "tornado.access INFO 304 GET /api/v1/settings/ (10.10.0.79) 4.10ms",
            "Serial_number: 332233 Batch_number: 0009",
            "Config: added 'key_mgmt' value 'WPA-PSK WPA-PSK-SHA256 FT-PSK'",
            "ssh_manager INFO Password already set: True",
            "pam_unix(chpasswd:chauthtok): password changed for root",
            "Listening on gpg-agent.socket - passphrase cache.",
            "device (lo): Activation: starting connection 'lo'",
            "Joining mDNS multicast group on interface lo.IPv6 with address ::1.",
            "2026-07-28 01:42:05.388326+00:00",
            # Zero-offset zones identify nobody, and "never synced its clock" is
            # exactly the signal needed to debug the timezone code itself.
            "systemd-timedated - Changed time zone to 'Etc/UTC' (UTC).",
            "CONF:   time_zone: Etc/UTC",
            # A parenthetical abbreviation with no zone in front of it must
            # survive, or the rule eats kernel messages.
            "kernel: Out of memory (OOM) killer invoked",
            "kernel: page allocation failure (NAND) on mmcblk0",
            "kernel: enabled Kernel Page Table Isolation (KPTI)",
            # A numeric-offset rule would have destroyed these.
            "ESP sensor bundle: -2404 -9815 -9252 -8911",
        ]
        for vector in vectors:
            with self.subTest(vector=vector):
                self.assertEqual(self.redact(vector), vector)

    def test_output_is_idempotent_and_preserves_line_count(self):
        text = (
            "Config: added 'ssid' value 'HomeNet'\n"
            "Associated with aa:bb:cc:dd:ee:ff\n"
            "root_password: synthetic-password\n"
        )
        once = self.redact(text)
        twice = self.redact(once)

        self.assertEqual(twice, once)
        self.assertEqual(
            len(text.splitlines(keepends=True)),
            len(once.splitlines(keepends=True)),
        )

    def test_json_quotes_and_structure_are_preserved(self):
        text = '{"root_password": "abc123", "serial": "332233"}'
        output = self.redact(text)

        self.assertEqual(
            json.loads(output),
            {"root_password": "[REDACTED]", "serial": "332233"},
        )

    def test_short_ssid_only_gets_anchored_coverage(self):
        text = "SSID='up'\nnetwork up is still visible"
        output = self.redact(text)

        self.assertRegex(output, r"SSID='\[SSID_[0-9a-f]{8}\]'")
        self.assertIn("network up is still visible", output)

    def test_key_is_persistent_and_private(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, ".redaction_key")
            first = load_key(path)
            second = load_key(path)

            self.assertEqual(len(first), 32)
            self.assertEqual(second, first)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_invalid_existing_key_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, ".redaction_key")
            with open(path, "wb") as key_file:
                key_file.write(b"too-short")

            with self.assertRaises(ValueError):
                load_key(path)

    def test_ten_megabyte_runtime_and_memory_budget(self):
        line = (
            "2026-07-28 01:42:05.388326+00:00 tornado.access INFO "
            "304 GET /api/v1/settings/ (10.10.0.79) 4.10ms\n"
        )
        text = line * ((10 * 1024 * 1024 // len(line)) + 1)

        started = time.monotonic()
        output = self.redact(text)
        elapsed = time.monotonic() - started
        peak_rss_kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        # Linux reports KiB, while macOS reports bytes for the same field.
        if sys.platform == "darwin":
            peak_rss_kib //= 1024

        self.assertEqual(output, text)
        self.assertLess(elapsed, 5)
        self.assertLess(peak_rss_kib, 128 * 1024)


class RedactionCancellationTests(unittest.TestCase):
    """redact()'s optional ``cancelled`` predicate: a caller may check it in
    pass 1 (the anchored-rule line loop) and pass 2 (the learned-SSID sweep)
    to abandon a run in progress. See log_collector.py in meticulous-watcher
    for the production caller."""

    def test_output_unchanged_when_predicate_never_signals(self):
        """A predicate that is checked repeatedly but never fires must not
        perturb output versus no predicate at all -- covers the KnownWifis
        indentation-tracking path alongside plain SSID/MAC/credential rules."""

        text = (
            "config DEBUG CONF:   wifi:\r\n"
            "config DEBUG CONF:     KnownWifis:\r\n"
            "config DEBUG CONF:       Some Network 5G:\r\n"
            "config DEBUG CONF:         password: example-pass\r\n"
            "config DEBUG CONF:         last_used: yesterday\n"
            "Config: added 'ssid' value 'HomeNet'\n"
            "wlan0: Trying to associate with SSID 'HomeNet'\n"
            "Associated with aa:bb:cc:dd:ee:ff\n"
        )

        baseline = redact(text, TEST_KEY)
        never_signals = redact(text, TEST_KEY, cancelled=lambda: False)

        self.assertEqual(baseline, never_signals)

    def test_predicate_signalling_during_pass_one_raises_and_yields_nothing(self):
        # 1200 lines cross check boundaries at line index 0, 500, 1000 --
        # False, False, True fires on the third, proving the check repeats
        # rather than firing only once at the very start.
        text = "".join(f"line {i}\n" for i in range(1200))
        cancelled = mock.Mock(side_effect=[False, False, True])

        with self.assertRaises(RedactionCancelled):
            redact(text, TEST_KEY, cancelled=cancelled)

        self.assertEqual(cancelled.call_count, 3)

    def test_predicate_signalling_during_pass_two_raises_and_yields_nothing(self):
        # One line, one learned SSID: pass 1's single check (index 0) must
        # return False so pass 1 completes and learns "HomeNet"; pass 2's
        # per-SSID check then fires before any sweep substitution.
        text = "Config: added 'ssid' value 'HomeNet'\n"
        cancelled = mock.Mock(side_effect=[False, True])

        with self.assertRaises(RedactionCancelled):
            redact(text, TEST_KEY, cancelled=cancelled)

        self.assertEqual(cancelled.call_count, 2)


if __name__ == "__main__":
    unittest.main()
