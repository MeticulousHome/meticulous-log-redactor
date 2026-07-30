"""Contract for the token strings this module produces.

meticulous-watcher and meticulous-backend both read the same per-device key from
/root/.redaction_key, which is the whole point: the same SSID has to produce the
same token in a backend log line and in the NetworkManager line beside it, or a
bug report contradicts itself and support cannot follow one network through it.

This file pins the exact output for a fixed key. If a rule, a token prefix, the
hash length, or the framing fed to HMAC changes, the expected strings below stop
matching. It runs here and in both consumers -- each against the submodule commit
it has checked out -- so a bad submodule bump fails the consumer's own test run
rather than surfacing as a report that contradicts itself.

If you are here because this test failed: do not update the expected values to
make it pass. Either the change was unintended and should be reverted, or it is
a deliberate rule change, in which case every already-collected report uses the
old tokens and that has to be a decision, not a test edit.
"""

import unittest

from log_redactor import pseudonym, redact

# Deliberately not bytes(range(32)) -- that is the other suite's key. A distinct
# key here means a copy-paste of expectations between suites cannot pass.
CONTRACT_KEY = b"\x00" * 32

# value -> exact token. Computed from HMAC-SHA256(key, f"{kind}\0{value}")[:8].
EXPECTED_TOKENS = {
    ("SSID", "HomeNet"): "[SSID_604cf397]",
    ("SSID", "Coffee Bar 2.4GHz"): "[SSID_6e4974a9]",
    ("MAC", "aa:bb:cc:dd:ee:ff"): "[MAC_cfe506c4]",
    ("IPV6", "fe80::1122:3344:5566:7788"): "[IPV6_4bf39a5b]",
}


class RedactionContractTests(unittest.TestCase):
    def test_token_values_are_pinned(self):
        for (kind, value), expected in EXPECTED_TOKENS.items():
            with self.subTest(kind=kind, value=value):
                self.assertEqual(pseudonym(kind, value, CONTRACT_KEY), expected)

    def test_pseudonym_matches_what_redact_emits(self):
        """The source-level entry point and the rules must agree.

        wifi.redact_ssid() in the backend pseudonymises at the call site via
        pseudonym(); the filter and the watcher reach the same value through
        redact(). Both have to land on the same token.
        """
        output, learned = redact("Config: added 'ssid' value 'HomeNet'", CONTRACT_KEY)
        self.assertEqual(learned, {"HomeNet"})
        self.assertEqual(output, "Config: added 'ssid' value '[SSID_604cf397]'")
        self.assertEqual(pseudonym("SSID", "HomeNet", CONTRACT_KEY), "[SSID_604cf397]")

    def test_end_to_end_vectors_are_pinned(self):
        """One vector per must-redact class, asserted as exact output."""
        vectors = [
            (
                "wlan0: Trying to associate with SSID 'HomeNet'",
                "wlan0: Trying to associate with SSID '[SSID_604cf397]'",
            ),
            (
                "SME: Trying to authenticate with aa:bb:cc:dd:ee:ff",
                "SME: Trying to authenticate with [MAC_cfe506c4]",
            ),
            (
                "Registering new address record for fe80::1122:3344:5566:7788",
                "Registering new address record for [IPV6_4bf39a5b]",
            ),
            (
                "CONF:   root_password: s3cr3tvalue",
                "CONF:   root_password: [REDACTED]",
            ),
            (
                "CONF:   APPassword: '123456789012'",
                "CONF:   APPassword: '[REDACTED]'",
            ),
            (
                "Changed time zone to 'America/Mexico_City' (CST).",
                "Changed time zone to 'America/*****' (*****).",
            ),
        ]
        for source, expected in vectors:
            with self.subTest(source=source):
                self.assertEqual(redact(source, CONTRACT_KEY)[0], expected)

    def test_case_folding_of_shape_matched_values_is_pinned(self):
        """MAC and IPv6 are lowercased before hashing; SSIDs are not.

        A NIC that logs its MAC uppercase in one subsystem and lowercase in
        another has to land on one token, or the report looks like two devices.
        An SSID is user text where case is significant, so it is hashed as-is.
        """
        upper = redact("set MAC address to AA:BB:CC:DD:EE:FF", CONTRACT_KEY)[0]
        self.assertEqual(upper, "set MAC address to [MAC_cfe506c4]")

        lower = redact("ssid: homenet", CONTRACT_KEY)[0]
        self.assertNotEqual(lower, "ssid: [SSID_604cf397]")


if __name__ == "__main__":
    unittest.main()
