"""
CRL (Certificate Revocation List) tests.
"""

from datetime import datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .. import models
from ..models import Feature, Importance, PeerKind
from ._core import Builder, ext, testcase


@testcase
def revoked_certificate_with_crl(builder: Builder) -> None:
    """
    Tests a Certificate Revocation List (CRL) that revokes a certificate.

    Produces a simple test case where a certificate has been revoked by the CA
    through a CRL. The CA certificate and CRL are provided, and the leaf certificate
    is expected to be rejected due to its revoked status.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    # Create a root CA
    root = builder.root_ca()

    # Create a leaf certificate
    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "revoked.example.com"),
            ]
        ),
        eku=ext(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False),
        san=ext(x509.SubjectAlternativeName([x509.DNSName("revoked.example.com")]), critical=False),
    )

    crl = builder.crl(
        signer=root,
        revoked=[
            x509.RevokedCertificateBuilder()
            .serial_number(leaf.cert.serial_number)
            .revocation_date(validation_time - timedelta(days=1))
            .build()
        ],
    )

    builder.features([Feature.has_crl]).importance(
        Importance.HIGH
    ).server_validation().trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        models.PeerName(kind=PeerKind.DNS, value="revoked.example.com")
    ).crls(crl).validation_time(validation_time).fails()


@testcase
def crlnumber_missing(builder: Builder) -> None:
    """
    Tests handling of a CRL that's missing the `CRLNumber` extension.

    Per RFC 5280 5.2.3 this extension MUST be included in a CRL.
    """

    root = builder.root_ca()

    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "missing-crlnumber.example.com"),
            ]
        ),
        eku=ext(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False),
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("missing-crlnumber.example.com")]),
            critical=False,
        ),
    )

    crl = builder.crl(
        signer=root,
        revoked=[
            # Revoke a random certificate here, not the leaf,
            # to ensure that we fail because the CRL is invalid,
            # not because the leaf is revoked.
            x509.RevokedCertificateBuilder()
            .serial_number(x509.random_serial_number())
            .revocation_date(leaf.cert.not_valid_before_utc + timedelta(seconds=1))
            .build()
        ],
        crl_number=None,
    )

    builder = (
        builder.features([Feature.has_crl])
        .importance(Importance.HIGH)
        .server_validation()
        .trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_name(
            models.PeerName(kind=PeerKind.DNS, value="missing-crlnumber.example.com")
        )
        .crls(crl)
        .validation_time(leaf.cert.not_valid_before_utc + timedelta(seconds=2))
        .fails()
    )


@testcase
def certificate_not_on_crl(builder: Builder) -> None:
    """
    Tests a certificate that is not present on any of the CRLs (expected pass).
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca()

    leaf = builder.leaf_cert(
        parent=root,
    )

    crl = builder.crl(
        signer=root,
        revoked=[
            x509.RevokedCertificateBuilder()
            .serial_number(x509.random_serial_number())
            .revocation_date(validation_time - timedelta(days=1))
            .build(),
            x509.RevokedCertificateBuilder()
            .serial_number(x509.random_serial_number())
            .revocation_date(validation_time - timedelta(days=2))
            .build(),
        ],
    )

    builder.features([Feature.has_crl]).importance(
        Importance.HIGH
    ).server_validation().trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        models.PeerName(kind=PeerKind.DNS, value="example.com")
    ).crls(crl).validation_time(validation_time).succeeds()


@testcase
def certificate_serial_on_crl_different_issuer(builder: Builder) -> None:
    """
    Tests a certificate whose serial number is found on a CRL, but that CRL
    has a different issuer than the certificate (expected pass).

    Produces a test case where a certificate's serial number appears on a CRL,
    but the CRL is issued by a different CA than the one that issued the
    certificate. The certificate should be accepted since the CRL from a
    different issuer should not affect this certificate's validity.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root_ca_1 = builder.root_ca(
        issuer=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA 1")]),
    )

    root_ca_2 = builder.root_ca(
        issuer=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA 2")]),
    )

    leaf = builder.leaf_cert(
        parent=root_ca_1,
    )

    crl1 = builder.crl(
        signer=root_ca_1,
        revoked=[],
    )

    crl2 = builder.crl(
        signer=root_ca_2,
        revoked=[
            x509.RevokedCertificateBuilder()
            .serial_number(leaf.cert.serial_number)  # Same serial as our leaf
            .revocation_date(validation_time - timedelta(days=1))
            .build()
        ],
    )

    builder.features([Feature.has_crl]).importance(
        Importance.HIGH
    ).server_validation().trusted_certs(root_ca_1, root_ca_2).peer_certificate(
        leaf
    ).expected_peer_name(models.PeerName(kind=PeerKind.DNS, value="example.com")).crls(
        crl1, crl2
    ).validation_time(validation_time).succeeds()


@testcase
def crlnumber_critical(builder: Builder) -> None:
    """
    Tests handling of a CRL that has a critical `CRLNumber` extension.

    Per RFC 5280 5.2.3, the `CRLNumber` extension is mandatory but MUST
    be marked as non-critical.
    """

    root = builder.root_ca()

    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "crlnumber-critical.example.com"),
            ]
        ),
        eku=ext(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False),
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("crlnumber-critical.example.com")]),
            critical=False,
        ),
    )

    crl = builder.crl(
        signer=root,
        revoked=[
            # Revoke a random certificate here, not the leaf,
            # to ensure that we fail because the CRL is invalid,
            # not because the leaf is revoked.
            x509.RevokedCertificateBuilder()
            .serial_number(x509.random_serial_number())
            .revocation_date(leaf.cert.not_valid_before_utc + timedelta(seconds=1))
            .build()
        ],
        crl_number=ext(x509.CRLNumber(12345), critical=True),
    )

    builder = (
        builder.features([Feature.has_crl])
        .importance(Importance.HIGH)
        .server_validation()
        .trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_name(
            models.PeerName(kind=PeerKind.DNS, value="crlnumber-critical.example.com")
        )
        .crls(crl)
        .validation_time(leaf.cert.not_valid_before_utc + timedelta(seconds=2))
        .fails()
    )


@testcase
def similar_certs_different_serials(builder: Builder) -> None:
    """
    Tests that CRL revocation matches only on serial number, not other attributes.

    Creates two certificates from the same CA with identical subject, public key,
    and validity period but different serial numbers. Only one serial is revoked.
    The non-revoked certificate should validate successfully, demonstrating that
    revocation is based solely on serial number within the issuer's namespace.

    This is the SUCCESS case - testing the certificate that is NOT revoked.
    """
    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca()

    shared_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "similar.example.com")])

    # Certificate A: serial 1000 (will be revoked)
    # We create this first to generate a key, then reuse that key for cert B
    cert_a = builder.leaf_cert(
        parent=root,
        serial=1000,
        subject=shared_subject,
        eku=ext(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False),
        san=ext(x509.SubjectAlternativeName([x509.DNSName("similar.example.com")]), critical=False),
    )

    # Certificate B: serial 2000 (NOT revoked) - this is the one we validate
    # Reuse the key from cert_a so both certificates have identical keys
    cert_b = builder.leaf_cert(
        parent=root,
        serial=2000,
        key=cert_a.key,
        subject=shared_subject,
        eku=ext(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False),
        san=ext(x509.SubjectAlternativeName([x509.DNSName("similar.example.com")]), critical=False),
    )

    # CRL revokes only serial 1000
    crl = builder.crl(
        signer=root,
        revoked=[
            x509.RevokedCertificateBuilder()
            .serial_number(1000)
            .revocation_date(validation_time - timedelta(days=1))
            .build()
        ],
    )

    # Certificate B (serial 2000) should succeed - it's not revoked
    builder.features([Feature.has_crl]).importance(
        Importance.HIGH
    ).server_validation().trusted_certs(root).peer_certificate(cert_b).expected_peer_name(
        models.PeerName(kind=PeerKind.DNS, value="similar.example.com")
    ).crls(crl).validation_time(validation_time).succeeds()


@testcase
def similar_certs_different_serials_revoked(builder: Builder) -> None:
    """
    Tests that CRL revocation correctly matches a certificate by serial number.

    Creates two certificates from the same CA with identical subject, public key,
    and validity period but different serial numbers. Tests that the certificate
    whose serial number appears on the CRL is correctly rejected.

    This is the FAILURE case - testing the certificate that IS revoked.
    """
    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca()

    shared_subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "similar-revoked.example.com")]
    )

    # Certificate A: serial 1000 (will be revoked) - this is the one we validate
    # We create this first to generate a key, then reuse that key for cert B
    cert_a = builder.leaf_cert(
        parent=root,
        serial=1000,
        subject=shared_subject,
        eku=ext(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False),
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("similar-revoked.example.com")]),
            critical=False,
        ),
    )

    # Certificate B: serial 2000 (NOT revoked)
    # We create this to demonstrate both exist but only one is revoked
    # Reuse the key from cert_a so both certificates have identical keys
    _cert_b = builder.leaf_cert(
        parent=root,
        serial=2000,
        key=cert_a.key,
        subject=shared_subject,
        eku=ext(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False),
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("similar-revoked.example.com")]),
            critical=False,
        ),
    )

    # CRL revokes only serial 1000
    crl = builder.crl(
        signer=root,
        revoked=[
            x509.RevokedCertificateBuilder()
            .serial_number(1000)
            .revocation_date(validation_time - timedelta(days=1))
            .build()
        ],
    )

    # Certificate A (serial 1000) should fail - it IS revoked
    builder.features([Feature.has_crl]).importance(
        Importance.HIGH
    ).server_validation().trusted_certs(root).peer_certificate(cert_a).expected_peer_name(
        models.PeerName(kind=PeerKind.DNS, value="similar-revoked.example.com")
    ).crls(crl).validation_time(validation_time).fails()


@testcase
def adjacent_serial_numbers(builder: Builder) -> None:
    """
    Tests that adjacent serial numbers are distinguished correctly in CRL matching.

    Creates two certificates with serial numbers that differ by only 1 (5000 and 5001).
    Revokes only serial 5000. The certificate with serial 5001 should validate
    successfully, ensuring implementations don't use approximate matching.
    """
    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca()

    # Certificate with serial 5001 (adjacent to revoked serial, but NOT revoked)
    leaf = builder.leaf_cert(
        parent=root,
        serial=5001,
        subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "adjacent-serial.example.com")]),
        eku=ext(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False),
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("adjacent-serial.example.com")]),
            critical=False,
        ),
    )

    # CRL revokes serial 5000 (adjacent to our certificate's serial)
    crl = builder.crl(
        signer=root,
        revoked=[
            x509.RevokedCertificateBuilder()
            .serial_number(5000)
            .revocation_date(validation_time - timedelta(days=1))
            .build()
        ],
    )

    # Certificate with serial 5001 should succeed - only 5000 is revoked
    builder.features([Feature.has_crl]).importance(
        Importance.HIGH
    ).server_validation().trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        models.PeerName(kind=PeerKind.DNS, value="adjacent-serial.example.com")
    ).crls(crl).validation_time(validation_time).succeeds()


@testcase
def small_serial_number_revocation(builder: Builder) -> None:
    """
    Tests CRL revocation of a certificate with a small serial number (1).

    While RFC 5280 requires serial numbers to be positive integers, very small
    values like 1 are valid. This test ensures implementations correctly handle
    revocation of certificates with minimal serial number values.
    """
    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca()

    # Certificate with serial 1 (smallest valid serial number)
    leaf = builder.leaf_cert(
        parent=root,
        serial=1,
        subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "small-serial.example.com")]),
        eku=ext(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False),
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("small-serial.example.com")]),
            critical=False,
        ),
    )

    # CRL revokes serial 1
    crl = builder.crl(
        signer=root,
        revoked=[
            x509.RevokedCertificateBuilder()
            .serial_number(1)
            .revocation_date(validation_time - timedelta(days=1))
            .build()
        ],
    )

    # Certificate should fail - serial 1 is revoked
    builder.features([Feature.has_crl]).importance(
        Importance.HIGH
    ).server_validation().trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        models.PeerName(kind=PeerKind.DNS, value="small-serial.example.com")
    ).crls(crl).validation_time(validation_time).fails()


@testcase
def large_serial_number_revocation(builder: Builder) -> None:
    """
    Tests CRL revocation of a certificate with a very large serial number.

    Per RFC 5280, serial numbers can be up to 20 octets. This test uses a
    large serial number (2^127) to ensure implementations correctly handle
    revocation matching for large serial number values.
    """
    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    # Large serial number (2^127, which is a 128-bit positive integer)
    large_serial = 2**127

    root = builder.root_ca()

    # Certificate with large serial number
    leaf = builder.leaf_cert(
        parent=root,
        serial=large_serial,
        subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "large-serial.example.com")]),
        eku=ext(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False),
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("large-serial.example.com")]),
            critical=False,
        ),
    )

    # CRL revokes the large serial number
    crl = builder.crl(
        signer=root,
        revoked=[
            x509.RevokedCertificateBuilder()
            .serial_number(large_serial)
            .revocation_date(validation_time - timedelta(days=1))
            .build()
        ],
    )

    # Certificate should fail - large serial is revoked
    builder.features([Feature.has_crl]).importance(
        Importance.HIGH
    ).server_validation().trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        models.PeerName(kind=PeerKind.DNS, value="large-serial.example.com")
    ).crls(crl).validation_time(validation_time).fails()
