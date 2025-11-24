"""
Test cases for CABF Baseline Requirements Section 7.1.4.3 compliance.

This section mandates that when a commonName (CN) field appears in TLS certificates,
it must exactly match one of the Subject Alternative Name (SAN) entries, character-for-character.
"""

from ipaddress import IPv4Address, IPv6Address

from cryptography import x509
from cryptography.x509.oid import NameOID

from limbo.models import PeerName
from limbo.testcases._core import Builder, testcase


@testcase
def cabf_cn_ipv4_hex_mismatch(builder: Builder) -> None:
    """
    Test that a certificate with CN containing IPv4 in hex format
    doesn't match the dotted-decimal SAN entry.

    CN: 0xC0A80101 (represents 192.168.1.1 in hex)
    SAN: 192.168.1.1 (dotted-decimal)
    """
    root = builder.root_ca()

    # Create certificate with hex format IPv4 in CN
    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "0xC0A80101"),
            ]
        ),
        san=x509.SubjectAlternativeName(
            [
                x509.IPAddress(IPv4Address("192.168.1.1")),
            ]
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="IP", value="192.168.1.1")
    ).fails()


@testcase
def cabf_cn_ipv4_leading_zeros_mismatch(builder: Builder) -> None:
    """
    Test that a certificate with CN containing IPv4 with leading zeros
    doesn't match the canonical SAN entry.

    CN: 192.168.001.001 (with leading zeros)
    SAN: 192.168.1.1 (canonical form)
    """
    root = builder.root_ca()

    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "192.168.001.001"),
            ]
        ),
        san=x509.SubjectAlternativeName(
            [
                x509.IPAddress(IPv4Address("192.168.1.1")),
            ]
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="IP", value="192.168.1.1")
    ).fails()


@testcase
def cabf_cn_ipv6_uppercase_mismatch(builder: Builder) -> None:
    """
    Test that a certificate with CN containing uppercase IPv6
    doesn't match the lowercase SAN entry.

    CN: 2001:DB8::8A2E:370:7334 (uppercase)
    SAN: 2001:db8::8a2e:370:7334 (lowercase)
    """
    root = builder.root_ca()

    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "2001:DB8::8A2E:370:7334"),
            ]
        ),
        san=x509.SubjectAlternativeName(
            [
                x509.IPAddress(IPv6Address("2001:db8::8a2e:370:7334")),
            ]
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="IP", value="2001:db8::8a2e:370:7334")
    ).fails()


@testcase
def cabf_cn_ipv6_uncompressed_mismatch(builder: Builder) -> None:
    """
    Test that a certificate with CN containing uncompressed IPv6
    doesn't match the compressed (RFC 5952) SAN entry.

    CN: 2001:0db8:0000:0000:0000:0000:0000:0001 (uncompressed)
    SAN: 2001:db8::1 (compressed per RFC 5952)
    """
    root = builder.root_ca()

    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "2001:0db8:0000:0000:0000:0000:0000:0001"),
            ]
        ),
        san=x509.SubjectAlternativeName(
            [
                x509.IPAddress(IPv6Address("2001:db8::1")),
            ]
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="IP", value="2001:db8::1")
    ).fails()


@testcase
def cabf_cn_ipv6_non_rfc5952_mismatch(builder: Builder) -> None:
    """
    Test that a certificate with CN containing non-RFC 5952 compliant IPv6
    doesn't match the RFC 5952 compliant SAN entry.

    CN: 2001:db8:0:0:1:0:0:1 (non-RFC 5952 - doesn't use :: for longest zero sequence)
    SAN: 2001:db8::1:0:0:1 (RFC 5952 compliant)
    """
    root = builder.root_ca()

    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "2001:db8:0:0:1:0:0:1"),
            ]
        ),
        san=x509.SubjectAlternativeName(
            [
                x509.IPAddress(IPv6Address("2001:db8::1:0:0:1")),
            ]
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="IP", value="2001:db8::1:0:0:1")
    ).fails()


@testcase
def cabf_cn_punycode_vs_utf8_mismatch(builder: Builder) -> None:
    """
    Test that a certificate with CN containing a different representation
    doesn't match the SAN entry.

    CN: xn--nxasmq6b.com (punycode)
    SAN: xn--n3h.com (punycode for different domain "⌘.com")

    This tests that CN must exactly match SAN, even when both are punycode.
    """
    root = builder.root_ca()

    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "xn--nxasmq6b.com"),
            ]
        ),
        san=x509.SubjectAlternativeName(
            [
                x509.DNSName("xn--n3h.com"),  # Different punycode domain
            ]
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="xn--n3h.com")
    ).fails()


@testcase
def cabf_cn_utf8_vs_punycode_mismatch(builder: Builder) -> None:
    """
    Test that a certificate with CN containing UTF-8
    doesn't match the punycode SAN entry when CN also needs to be in punycode.

    CN: test-測試.com (UTF-8 characters, but should be xn--test--wg5h0h.com)
    SAN: xn--test--wg5h0h.com (correct punycode)
    """
    root = builder.root_ca()

    # Note: The CN contains UTF-8, which is technically invalid in X.509,
    # but we're testing that validators properly reject when CN != SAN
    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "test-測試.com"),
            ]
        ),
        san=x509.SubjectAlternativeName(
            [
                x509.DNSName("xn--test--wg5h0h.com"),  # Correct punycode encoding
            ]
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="xn--test--wg5h0h.com")
    ).fails()


@testcase
def cabf_cn_not_in_san(builder: Builder) -> None:
    """
    Test that a certificate with CN that doesn't match any SAN entry fails.

    CN: notinsan.example.com
    SAN: valid.example.com, another.example.com
    """
    root = builder.root_ca()

    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "notinsan.example.com"),
            ]
        ),
        san=x509.SubjectAlternativeName(
            [
                x509.DNSName("valid.example.com"),
                x509.DNSName("another.example.com"),
            ]
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="valid.example.com")
    ).fails()


@testcase
def cabf_cn_case_mismatch(builder: Builder) -> None:
    """
    Test that a certificate with CN differing in case from SAN entry fails.

    CN: Example.COM
    SAN: example.com
    """
    root = builder.root_ca()

    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "Example.COM"),
            ]
        ),
        san=x509.SubjectAlternativeName(
            [
                x509.DNSName("example.com"),
            ]
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()
