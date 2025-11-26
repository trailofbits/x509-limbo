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
def leaf_with_cdp_extension(builder: Builder) -> None:
    """
    Tests a leaf certificate with a CRL Distribution Points (CDP) extension.

    This test verifies basic CDP extension handling. The leaf certificate includes
    a CDP extension pointing to a CRL distribution point (as a URI), and the
    certificate should be accepted as valid when the CRL shows no revocation.

    This tests RFC 5280 Section 4.2.1.13 (CRL Distribution Points extension).
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca()

    # Create CDP extension with a distribution point
    cdp = ext(
        x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier("http://example.com/root.crl")],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None,
                )
            ]
        ),
        critical=False,
    )

    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "cdp.example.com"),
            ]
        ),
        eku=ext(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False),
        san=ext(x509.SubjectAlternativeName([x509.DNSName("cdp.example.com")]), critical=False),
        extra_extension=cdp,
    )

    crl = builder.crl(
        signer=root,
        revoked=[],
    )

    builder.features([Feature.has_crl]).importance(
        Importance.MEDIUM
    ).server_validation().trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        models.PeerName(kind=PeerKind.DNS, value="cdp.example.com")
    ).crls(crl).validation_time(validation_time).succeeds()


@testcase
def cdp_with_indirect_crl_issuer(builder: Builder) -> None:
    """
    Tests CDP extension with cRLIssuer field authorizing an indirect CRL.

    Per RFC 5280 Section 6.3.3 step (b)(2), when a CDP extension includes
    a cRLIssuer field, the CRL issuer does not need to match the certificate
    issuer. This test verifies that an indirect CRL (issued by a different CA)
    is accepted when authorized via the cRLIssuer field in the CDP extension.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    # Create two separate CAs
    cert_issuer = builder.root_ca(
        issuer=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Certificate Issuer CA")]),
    )

    crl_issuer = builder.root_ca(
        issuer=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CRL Issuer CA")]),
    )

    # Create CDP extension with cRLIssuer pointing to the different CRL issuer
    cdp = ext(
        x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier("http://example.com/indirect.crl")],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=[x509.DirectoryName(crl_issuer.cert.subject)],
                )
            ]
        ),
        critical=False,
    )

    leaf = builder.leaf_cert(
        parent=cert_issuer,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "indirect-crl.example.com"),
            ]
        ),
        eku=ext(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False),
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("indirect-crl.example.com")]),
            critical=False,
        ),
        extra_extension=cdp,
    )

    # Create CRL from the CRL issuer (not the cert issuer)
    crl = builder.crl(
        signer=crl_issuer,
        revoked=[],
    )

    builder.features([Feature.has_crl]).importance(
        Importance.MEDIUM
    ).server_validation().trusted_certs(cert_issuer, crl_issuer).peer_certificate(
        leaf
    ).expected_peer_name(models.PeerName(kind=PeerKind.DNS, value="indirect-crl.example.com")).crls(
        crl
    ).validation_time(validation_time).succeeds()


@testcase
def cdp_without_crl_issuer_rejects_indirect_crl(builder: Builder) -> None:
    """
    Tests that CDP without cRLIssuer requires direct issuer matching.

    Per RFC 5280 Section 6.3.3 step (b)(1), when a CDP extension does NOT
    include a cRLIssuer field, the CRL issuer MUST match the certificate issuer.
    This test verifies that an indirect CRL (from a different issuer) is rejected
    when the CDP does not authorize it via cRLIssuer.
    """

    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    # Create two separate CAs
    cert_issuer = builder.root_ca(
        issuer=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Certificate Issuer CA")]),
    )

    wrong_crl_issuer = builder.root_ca(
        issuer=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Wrong CRL Issuer CA")]),
    )

    # Create CDP extension WITHOUT cRLIssuer (only has distribution point URI)
    cdp = ext(
        x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier("http://example.com/direct.crl")],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None,  # No cRLIssuer - requires direct matching
                )
            ]
        ),
        critical=False,
    )

    leaf = builder.leaf_cert(
        parent=cert_issuer,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "direct-only.example.com"),
            ]
        ),
        eku=ext(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False),
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("direct-only.example.com")]),
            critical=False,
        ),
        extra_extension=cdp,
    )

    # Provide the correct CRL from cert_issuer
    correct_crl = builder.crl(
        signer=cert_issuer,
        revoked=[],
    )

    # Also provide a CRL from wrong issuer (should be ignored)
    wrong_crl = builder.crl(
        signer=wrong_crl_issuer,
        revoked=[
            # Try to revoke the leaf certificate
            x509.RevokedCertificateBuilder()
            .serial_number(leaf.cert.serial_number)
            .revocation_date(validation_time - timedelta(days=1))
            .build()
        ],
    )

    # The certificate should succeed because:
    # 1. CDP doesn't have cRLIssuer, so only cert_issuer's CRL applies
    # 2. cert_issuer's CRL doesn't revoke the certificate
    # 3. wrong_crl_issuer's CRL should be ignored (issuer mismatch)
    builder.features([Feature.has_crl]).importance(
        Importance.HIGH
    ).server_validation().trusted_certs(cert_issuer, wrong_crl_issuer).peer_certificate(
        leaf
    ).expected_peer_name(models.PeerName(kind=PeerKind.DNS, value="direct-only.example.com")).crls(
        correct_crl, wrong_crl
    ).validation_time(validation_time).succeeds()
