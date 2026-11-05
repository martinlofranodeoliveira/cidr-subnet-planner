"""Tests for strict CIDR parsing, host-bit diagnostics, addressing profiles, and scope classification."""

from __future__ import annotations

import unittest

from cidr_planner.errors import (
    CIDRValidationError,
    NonCanonicalCIDRError,
    ResourceLimitExceededError,
)
from cidr_planner.limits import PlannerLimits
from cidr_planner.parser import inspect_cidr, parse_cidr
from cidr_planner.profiles import (
    calculate_addressing_metrics,
    prefix_length_for_Required_hosts,
)
from cidr_planner.scopes import classify_prefix_scope


class StrictParserAndProfilesTests(unittest.TestCase):
    """Verify strict CIDR grammar, non-canonical host-bit rejection, and profile math."""

    def test_canonical_ipv4_and_ipv6_parsing(self) -> None:
        v4 = parse_cidr("10.10.4.0/22", strict=True)
        self.assertEqual(v4.canonical_cidr, "10.10.4.0/22")
        self.assertEqual(v4.family, "ipv4")
        self.assertTrue(v4.is_canonical_host_bits)
        self.assertEqual(v4.address_count, 1024)

        v6 = parse_cidr("2001:db8:abcd::/48", strict=True)
        self.assertEqual(v6.canonical_cidr, "2001:db8:abcd::/48")
        self.assertEqual(v6.family, "ipv6")
        self.assertTrue(v6.is_canonical_host_bits)
        self.assertEqual(v6.address_count, 1 << 80)

    def test_strict_mode_rejects_nonzero_host_bits_with_canonical_suggestion(self) -> None:
        with self.assertRaises(NonCanonicalCIDRError) as ctx:
            parse_cidr("192.168.1.42/24", strict=True)
        err = ctx.exception
        self.assertEqual(err.code, "non_canonical_host_bits")
        self.assertEqual(err.input_cidr, "192.168.1.42/24")
        self.assertEqual(err.canonical_cidr, "192.168.1.0/24")
        self.assertEqual(err.host_bits_hex, "0x2a")
        self.assertEqual(err.family, "ipv4")

        # Non-strict inspect preserves both input and canonical suggestion
        inspected = inspect_cidr("10.0.1.5/24")
        self.assertFalse(inspected.is_canonical_host_bits)
        self.assertEqual(inspected.input_cidr, "10.0.1.5/24")
        self.assertEqual(inspected.canonical_cidr, "10.0.1.0/24")
        self.assertEqual(inspected.host_bits_int, 5)

        # IPv6 non-canonical host bits
        with self.assertRaises(NonCanonicalCIDRError) as v6_ctx:
            parse_cidr("2001:db8::1/64", strict=True)
        self.assertEqual(v6_ctx.exception.canonical_cidr, "2001:db8::/64")
        self.assertEqual(v6_ctx.exception.host_bits_hex, "0x1")

    def test_rejects_impostor_types_and_malformed_grammar(self) -> None:
        for impostor in (True, False, 12345, None, ["10.0.0.0/8"], {"cidr": "10.0.0.0/8"}):
            with self.assertRaises(CIDRValidationError) as ctx:
                parse_cidr(impostor)  # type: ignore[arg-type]
            self.assertEqual(ctx.exception.code, "invalid_cidr_type")

        invalid_cases = [
            ("", "empty_cidr_string"),
            (" 10.0.0.0/8", "invalid_cidr_whitespace"),
            ("10.0.0.0/8 ", "invalid_cidr_whitespace"),
            ("fe80::1%eth0/64", "ipv6_scope_zone_not_supported"),
            ("10.0.0.0", "missing_or_invalid_prefix_separator"),
            ("10.0.0.0/8/16", "missing_or_invalid_prefix_separator"),
            ("10.0.0.0/255.255.255.0", "netmask_or_hostmask_not_supported"),
            ("10.0.0.0/0.0.0.255", "netmask_or_hostmask_not_supported"),
            ("10.0.0.0/08", "leading_zero_in_prefix_length"),
            ("10.0.0.0/+24", "invalid_prefix_length"),
            ("10.0.0.0/-1", "invalid_prefix_length"),
            ("10.0.0.0/33", "prefix_length_out_of_range"),
            ("2001:db8::/129", "prefix_length_out_of_range"),
            ("999.999.999.999/24", "invalid_ip_address"),
        ]
        for raw, expected_code in invalid_cases:
            with self.subTest(raw=raw):
                with self.assertRaises(CIDRValidationError) as ctx:
                    parse_cidr(raw, strict=True)
                self.assertEqual(ctx.exception.code, expected_code)

    def test_cidr_string_length_bound(self) -> None:
        tight_limits = PlannerLimits(max_cidr_string_length=12)
        with self.assertRaises(ResourceLimitExceededError) as ctx:
            parse_cidr("192.168.100.0/24", limits=tight_limits)
        self.assertEqual(ctx.exception.limit_name, "max_cidr_string_length")

    def test_addressing_profiles_ipv4_and_ipv6_precision(self) -> None:
        # /24 standard_ipv4 -> 256 total, 254 usable
        m24 = calculate_addressing_metrics("10.0.0.0/24", profile="standard_ipv4")
        self.assertEqual(m24["total_addresses"], 256)
        self.assertEqual(m24["usable_hosts"], 254)
        self.assertEqual(m24["first_usable_address"], "10.0.0.1")
        self.assertEqual(m24["last_usable_address"], "10.0.0.254")

        # /30 standard_ipv4 -> 4 total, 2 usable
        m30 = calculate_addressing_metrics("10.0.0.0/30", profile="standard_ipv4")
        self.assertEqual(m30["total_addresses"], 4)
        self.assertEqual(m30["usable_hosts"], 2)

        # /31 standard_ipv4 -> 0 usable hosts
        m31_std = calculate_addressing_metrics("10.0.0.0/31", profile="standard_ipv4")
        self.assertEqual(m31_std["total_addresses"], 2)
        self.assertEqual(m31_std["usable_hosts"], 0)
        self.assertIsNone(m31_std["first_usable_address"])

        # /31 rfc3021_p2p -> 2 usable hosts
        m31_p2p = calculate_addressing_metrics("10.0.0.0/31", profile="rfc3021_p2p")
        self.assertEqual(m31_p2p["total_addresses"], 2)
        self.assertEqual(m31_p2p["usable_hosts"], 2)
        self.assertEqual(m31_p2p["first_usable_address"], "10.0.0.0")
        self.assertEqual(m31_p2p["last_usable_address"], "10.0.0.1")

        # /32 single-host -> 1 usable host
        m32 = calculate_addressing_metrics("10.0.0.99/32", profile="standard_ipv4")
        self.assertEqual(m32["total_addresses"], 1)
        self.assertEqual(m32["usable_hosts"], 1)

        # /0 standard_ipv4 -> 2^32 - 2 usable
        m0_v4 = calculate_addressing_metrics("0.0.0.0/0", profile="standard_ipv4")
        self.assertEqual(m0_v4["total_addresses"], 4294967296)
        self.assertEqual(m0_v4["usable_hosts"], 4294967294)

        # IPv6 /64 and /0 preserve 128-bit precision as decimal strings
        m64_v6 = calculate_addressing_metrics("2001:db8::/64", profile="ipv6")
        self.assertEqual(m64_v6["total_addresses"], "18446744073709551616")
        self.assertEqual(m64_v6["usable_hosts"], "18446744073709551616")

        m0_v6 = calculate_addressing_metrics("::/0", profile="ipv6")
        self.assertEqual(m0_v6["total_addresses"], str(1 << 128))

    def test_prefix_length_for_required_hosts(self) -> None:
        self.assertEqual(prefix_length_for_Required_hosts(1, version=4, profile="standard_ipv4"), 32)
        self.assertEqual(prefix_length_for_Required_hosts(2, version=4, profile="standard_ipv4"), 30)
        self.assertEqual(prefix_length_for_Required_hosts(2, version=4, profile="rfc3021_p2p"), 31)
        self.assertEqual(prefix_length_for_Required_hosts(50, version=4, profile="standard_ipv4"), 26)
        self.assertEqual(prefix_length_for_Required_hosts(254, version=4, profile="standard_ipv4"), 24)
        self.assertEqual(prefix_length_for_Required_hosts(255, version=4, profile="standard_ipv4"), 23)


class ScopeClassificationTests(unittest.TestCase):
    """Verify explicit CIDR range snapshot classification, fallback, and mixed-scope detection."""

    def test_explicit_single_scopes_and_conservative_fallback(self) -> None:
        cases = [
            ("0.0.0.0/8", "this_network"),
            ("10.24.0.0/16", "private_rfc1918"),
            ("172.20.0.0/16", "private_rfc1918"),
            ("192.168.10.0/24", "private_rfc1918"),
            ("100.64.10.0/24", "shared_cgnat"),
            ("127.0.0.1/32", "loopback"),
            ("169.254.169.254/32", "link_local"),
            ("192.0.2.0/24", "documentation"),
            ("198.51.100.0/24", "documentation"),
            ("203.0.113.0/24", "documentation"),
            ("198.18.0.0/15", "benchmarking"),
            ("224.0.0.0/24", "multicast"),
            ("240.0.0.0/4", "future_reserved"),
            # Unclassified public/other blocks must use conservative fallback, NEVER global_unicast
            ("8.8.8.0/24", "other_or_reserved"),
            ("1.1.1.0/24", "other_or_reserved"),
            ("::/128", "unspecified"),
            ("::1/128", "loopback"),
            ("2001:db8:1234::/48", "documentation"),
            ("fd12:3456:789a::/48", "unique_local"),
            ("fe80::/64", "link_local"),
            ("ff02::/16", "multicast"),
            ("2606:4700::/32", "other_or_reserved"),
        ]
        for cidr, expected_scope in cases:
            with self.subTest(cidr=cidr):
                res = classify_prefix_scope(cidr)
                self.assertEqual(res.scope, expected_scope)
                self.assertEqual(res.matched_scopes, (expected_scope,))

    def test_ipv4_and_ipv6_slash_zero_are_mixed(self) -> None:
        v4_all = classify_prefix_scope("0.0.0.0/0")
        self.assertEqual(v4_all.scope, "mixed")
        self.assertIn("private_rfc1918", v4_all.matched_scopes)
        self.assertIn("loopback", v4_all.matched_scopes)
        self.assertIn("link_local", v4_all.matched_scopes)
        self.assertIn("multicast", v4_all.matched_scopes)
        self.assertIn("documentation", v4_all.matched_scopes)
        self.assertIn("other_or_reserved", v4_all.matched_scopes)

        v6_all = classify_prefix_scope("::/0")
        self.assertEqual(v6_all.scope, "mixed")
        self.assertIn("loopback", v6_all.matched_scopes)
        self.assertIn("unique_local", v6_all.matched_scopes)
        self.assertIn("link_local", v6_all.matched_scopes)
        self.assertIn("multicast", v6_all.matched_scopes)
        self.assertIn("documentation", v6_all.matched_scopes)
        self.assertIn("other_or_reserved", v6_all.matched_scopes)

    def test_straddling_prefixes_are_marked_mixed_even_when_first_address_is_special(self) -> None:
        straddling_cases = [
            # Starts in private 10.0.0.0/8, extends into 11.0.0.0/8 (other_or_reserved)
            ("10.0.0.0/7", ("private_rfc1918", "other_or_reserved")),
            # Starts in 126.0.0.0/8 (other_or_reserved), extends into 127.0.0.0/8 (loopback)
            ("126.0.0.0/7", ("loopback", "other_or_reserved")),
            # Starts in 169.254.0.0/16 (link_local), extends into 169.255.0.0/16 (other_or_reserved)
            ("169.254.0.0/15", ("link_local", "other_or_reserved")),
            # Starts in 192.0.2.0/24 (documentation), extends into 192.0.3.0/24 (other_or_reserved)
            ("192.0.2.0/23", ("documentation", "other_or_reserved")),
            # Spans 224.0.0.0/4 (multicast) and 240.0.0.0/4 (future_reserved)
            ("224.0.0.0/3", ("multicast", "future_reserved")),
            # Spans ::/128 (unspecified) and ::1/128 (loopback)
            ("::/127", ("unspecified", "loopback")),
            # Starts in 2001:db8::/32 (documentation), extends into 2001:db9::/32 (other_or_reserved)
            ("2001:db8::/31", ("documentation", "other_or_reserved")),
            # Starts in fe80::/10 (link_local), extends into fec0::/10 (other_or_reserved)
            ("fe80::/9", ("link_local", "other_or_reserved")),
        ]
        for cidr, expected_matched in straddling_cases:
            with self.subTest(cidr=cidr):
                res = classify_prefix_scope(cidr)
                self.assertEqual(res.scope, "mixed")
                self.assertEqual(res.matched_scopes, expected_matched)


if __name__ == "__main__":
    unittest.main()
