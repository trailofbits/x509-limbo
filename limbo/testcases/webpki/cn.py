"""
Test cases for CABF Baseline Requirements Section 7.1.4.3 compliance.

CABF BR v2.1.9 Section 7.1.4.3 (Subscriber Certificate Common Name Attribute) states:

    "If present, this attribute MUST contain exactly one entry that is one of the
    values contained in the Certificate's subjectAltName extension (see Section
    7.1.2.7.12). The value of the field MUST be encoded as follows:

    - If the value is an IPv4 address, then the value MUST be encoded as an
      IPv4Address as specified in RFC 3986, Section 3.2.2.
    - If the value is an IPv6 address, then the value MUST be encoded in the text
      representation specified in RFC 5952, Section 4.
    - If the value is a Fully-Qualified Domain Name or Wildcard Domain Name, then
      the value MUST be encoded as a character-for-character copy of the dNSName
      entry value from the subjectAltName extension. Specifically, all Domain
      Labels of the Fully-Qualified Domain Name or FQDN portion of the Wildcard
      Domain Name must be encoded as LDH Labels, and P-Labels MUST NOT be converted
      to their Unicode representation."

These test cases verify that certificates violating these requirements are rejected.
"""

from ipaddress import IPv4Address, IPv6Address

from cryptography import x509
from cryptography.x509.oid import NameOID

from limbo.assets import ext
from limbo.models import PeerName
from limbo.testcases._core import Builder, testcase


@testcase
def cabf_cn_ipv4_hex_mismatch(builder: Builder) -> None:
    """
    Produces a certificate where the CN contains an IPv4 address in hexadecimal
    format, which violates CABF BR 7.1.4.3.

    CABF BR 7.1.4.3 requires: "If the value is an IPv4 address, then the value
    MUST be encoded as an IPv4Address as specified in RFC 3986, Section 3.2.2."

    RFC 3986 Section 3.2.2 defines the IPv4address grammar using only decimal
    octets separated by periods (dotted-decimal notation). Hexadecimal format
    is not permitted by this grammar.

    > IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet

    CN: 0xC0A80101 (invalid - hexadecimal format, represents 192.168.1.1)
    SAN: 192.168.1.1 (valid RFC 3986 dotted-decimal format)

    The certificate MUST be rejected because the CN is not a valid IPv4 address
    per the required encoding format.
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
        san=ext(
            x509.SubjectAlternativeName(
                [
                    x509.IPAddress(IPv4Address("192.168.1.1")),
                ]
            ),
            critical=False,
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="IP", value="192.168.1.1")
    ).fails()


@testcase
def cabf_cn_ipv4_leading_zeros_mismatch(builder: Builder) -> None:
    """
    Produces a certificate where the CN contains an IPv4 address with leading
    zeros, which violates CABF BR 7.1.4.3.

    CABF BR 7.1.4.3 requires: "If the value is an IPv4 address, then the value
    MUST be encoded as an IPv4Address as specified in RFC 3986, Section 3.2.2."

    RFC 3986 Section 3.2.2 defines the dec-octet grammar as:

    > dec-octet = DIGIT / %x31-39 DIGIT / "1" 2DIGIT / "2" %x30-34 DIGIT
    >           / "25" %x30-35

    This grammar does not permit leading zeros (e.g., "001" is not valid because
    a three-digit octet must start with "1" or "2").

    CN: 192.168.001.001 (invalid - contains leading zeros)
    SAN: 192.168.1.1 (valid RFC 3986 format)

    The certificate MUST be rejected because the CN is not a valid IPv4 address
    per the required encoding format.
    """
    root = builder.root_ca()

    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "192.168.001.001"),
            ]
        ),
        san=ext(
            x509.SubjectAlternativeName(
                [
                    x509.IPAddress(IPv4Address("192.168.1.1")),
                ]
            ),
            critical=False,
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="IP", value="192.168.1.1")
    ).fails()


@testcase
def cabf_cn_ipv6_uppercase_mismatch(builder: Builder) -> None:
    """
    Produces a certificate where the CN contains an IPv6 address with uppercase
    hexadecimal characters, which violates CABF BR 7.1.4.3.

    CABF BR 7.1.4.3 requires: "If the value is an IPv6 address, then the value
    MUST be encoded in the text representation specified in RFC 5952, Section 4."

    RFC 5952 Section 4 states:

    > The characters "a", "b", "c", "d", "e", and "f" in an IPv6 address MUST
    > be represented in lowercase.

    CN: 2001:DB8::8A2E:370:7334 (invalid - contains uppercase hex characters)
    SAN: 2001:db8::8a2e:370:7334 (valid RFC 5952 format with lowercase)

    The certificate MUST be rejected because the CN is not a valid IPv6 address
    per the required RFC 5952 text representation.
    """
    root = builder.root_ca()

    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "2001:DB8::8A2E:370:7334"),
            ]
        ),
        san=ext(
            x509.SubjectAlternativeName(
                [
                    x509.IPAddress(IPv6Address("2001:db8::8a2e:370:7334")),
                ]
            ),
            critical=False,
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="IP", value="2001:db8::8a2e:370:7334")
    ).fails()


@testcase
def cabf_cn_ipv6_uncompressed_mismatch(builder: Builder) -> None:
    """
    Produces a certificate where the CN contains an uncompressed IPv6 address
    with leading zeros and no "::" compression, which violates CABF BR 7.1.4.3.

    CABF BR 7.1.4.3 requires: "If the value is an IPv6 address, then the value
    MUST be encoded in the text representation specified in RFC 5952, Section 4."

    RFC 5952 Section 4 states:

    > Leading zeros MUST be suppressed. For example, 2001:0db8::0001 is not
    > acceptable and must be represented as 2001:db8::1.

    > The use of "::" MUST be used to its maximum capability.

    CN: 2001:0db8:0000:0000:0000:0000:0000:0001 (invalid - has leading zeros
        and doesn't use "::" compression)
    SAN: 2001:db8::1 (valid RFC 5952 format)

    The certificate MUST be rejected because the CN is not a valid IPv6 address
    per the required RFC 5952 text representation.
    """
    root = builder.root_ca()

    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "2001:0db8:0000:0000:0000:0000:0000:0001"),
            ]
        ),
        san=ext(
            x509.SubjectAlternativeName(
                [
                    x509.IPAddress(IPv6Address("2001:db8::1")),
                ]
            ),
            critical=False,
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="IP", value="2001:db8::1")
    ).fails()


@testcase
def cabf_cn_ipv6_non_rfc5952_mismatch(builder: Builder) -> None:
    """
    Produces a certificate where the CN contains an IPv6 address that doesn't
    use "::" compression for the longest zero sequence, violating CABF BR 7.1.4.3.

    CABF BR 7.1.4.3 requires: "If the value is an IPv6 address, then the value
    MUST be encoded in the text representation specified in RFC 5952, Section 4."

    RFC 5952 Section 4 states:

    > The use of "::" MUST be used to its maximum capability. For example,
    > 2001:db8:0:0:0:0:2:1 must be shortened to 2001:db8::2:1.

    > When there is an alternative choice in the placement of a "::", the first
    > sequence of zero bits MUST be shortened.

    CN: 2001:db8:0:0:1:0:0:1 (invalid - doesn't use "::" for the first longest
        zero sequence at positions 3-4)
    SAN: 2001:db8::1:0:0:1 (valid RFC 5952 format with "::" at first zero run)

    The certificate MUST be rejected because the CN is not a valid IPv6 address
    per the required RFC 5952 text representation.
    """
    root = builder.root_ca()

    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "2001:db8:0:0:1:0:0:1"),
            ]
        ),
        san=ext(
            x509.SubjectAlternativeName(
                [
                    x509.IPAddress(IPv6Address("2001:db8::1:0:0:1")),
                ]
            ),
            critical=False,
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="IP", value="2001:db8::1:0:0:1")
    ).fails()


@testcase
def cabf_cn_punycode_not_in_san(builder: Builder) -> None:
    """
    Produces a certificate where the CN contains a punycode domain that is not
    present in the SAN, violating CABF BR 7.1.4.3.

    CABF BR 7.1.4.3 requires: "If present, this attribute MUST contain exactly
    one entry that is one of the values contained in the Certificate's
    subjectAltName extension."

    CN: xn--nxasmq6b.com (punycode for "בדיקה.com")
    SAN: xn--n3h.com (punycode for "⌘.com" - a different domain)

    The certificate MUST be rejected because the CN value does not match any
    of the SAN entries.
    """
    root = builder.root_ca()

    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "xn--nxasmq6b.com"),
            ]
        ),
        san=ext(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("xn--n3h.com"),  # Different punycode domain
                ]
            ),
            critical=False,
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="xn--n3h.com")
    ).fails()


@testcase
def cabf_cn_utf8_vs_punycode_mismatch(builder: Builder) -> None:
    """
    Produces a certificate where the CN contains a UTF-8 internationalized
    domain name while the SAN contains the punycode equivalent, violating
    CABF BR 7.1.4.3.

    CABF BR 7.1.4.3 requires: "If the value is a Fully-Qualified Domain Name
    or Wildcard Domain Name, then the value MUST be encoded as a
    character-for-character copy of the dNSName entry value from the
    subjectAltName extension."

    The CN value "test-測試.com" (UTF-8) is not a character-for-character
    copy of the SAN value "xn--test--wg5h0h.com" (punycode), even though
    they represent the same domain semantically.

    CN: test-測試.com (UTF-8 representation)
    SAN: xn--test--wg5h0h.com (punycode/A-label representation)

    The certificate MUST be rejected because the CN is not a
    character-for-character copy of the SAN dNSName entry.
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
        san=ext(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("xn--test--wg5h0h.com"),  # Correct punycode encoding
                ]
            ),
            critical=False,
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="xn--test--wg5h0h.com")
    ).fails()


@testcase
def cabf_cn_not_in_san(builder: Builder) -> None:
    """
    Produces a certificate where the CN contains a domain name that is not
    present in any SAN entry, violating CABF BR 7.1.4.3.

    CABF BR 7.1.4.3 requires: "If present, this attribute MUST contain exactly
    one entry that is one of the values contained in the Certificate's
    subjectAltName extension."

    CN: notinsan.example.com
    SAN: valid.example.com, another.example.com

    The certificate MUST be rejected because the CN value "notinsan.example.com"
    does not match any of the SAN dNSName entries.
    """
    root = builder.root_ca()

    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "notinsan.example.com"),
            ]
        ),
        san=ext(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("valid.example.com"),
                    x509.DNSName("another.example.com"),
                ]
            ),
            critical=False,
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="valid.example.com")
    ).fails()


@testcase
def cabf_cn_case_mismatch(builder: Builder) -> None:
    """
    Produces a certificate where the CN differs from the SAN entry only in
    letter case, violating CABF BR 7.1.4.3.

    CABF BR 7.1.4.3 requires: "If the value is a Fully-Qualified Domain Name
    or Wildcard Domain Name, then the value MUST be encoded as a
    character-for-character copy of the dNSName entry value from the
    subjectAltName extension."

    The requirement for a "character-for-character copy" means that the CN
    must be byte-identical to the SAN entry. "Example.COM" differs from
    "example.com" in the bytes representing 'E', 'C', 'O', and 'M'.

    CN: Example.COM (mixed case)
    SAN: example.com (lowercase)

    The certificate MUST be rejected because the CN is not a
    character-for-character copy of the SAN dNSName entry.
    """
    root = builder.root_ca()

    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "Example.COM"),
            ]
        ),
        san=ext(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("example.com"),
                ]
            ),
            critical=False,
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()
