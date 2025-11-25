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
def issuer_mismatch_root_vs_intermediate(builder: Builder) -> None:
    """
    Tests that a CRL issued by a root CA does not apply to certificates
    issued by an intermediate CA, even if the CRL lists the certificate's serial.

    Per RFC 5280 Section 6.3.3, the CRL issuer must match the certificate issuer.
    A CRL from the root CA should not affect certificates issued by intermediates.
    """
    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca(issuer=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")]))

    intermediate = builder.intermediate_ca(
        parent=root,
        subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate CA")]),
        pathlen=0,
        key_usage=ext(
            x509.KeyUsage(
                digital_signature=False,
                key_cert_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=False,
        ),
    )

    leaf = builder.leaf_cert(parent=intermediate)

    # CRL from root CA listing the leaf's serial - should not apply
    crl_from_root = builder.crl(
        signer=root,
        revoked=[
            x509.RevokedCertificateBuilder()
            .serial_number(leaf.cert.serial_number)
            .revocation_date(validation_time - timedelta(days=1))
            .build()
        ],
    )

    # Also provide a valid (empty) CRL from the intermediate
    crl_from_intermediate = builder.crl(signer=intermediate, revoked=[])

    builder.features([Feature.has_crl]).importance(
        Importance.HIGH
    ).server_validation().trusted_certs(root).untrusted_intermediates(
        intermediate
    ).peer_certificate(leaf).expected_peer_name(
        models.PeerName(kind=PeerKind.DNS, value="example.com")
    ).crls(crl_from_root, crl_from_intermediate).validation_time(validation_time).succeeds()


@testcase
def crl_issuer_name_signature_mismatch(builder: Builder) -> None:
    """
    Tests that a CRL with an issuer name that doesn't match the signer is rejected.

    The CRL is signed by the root CA but claims a different issuer name.
    Per RFC 5280, the CRL issuer name must match the certificate issuer,
    and the CRL signature must be verifiable by that issuer's key.
    """
    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca(issuer=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")]))
    leaf = builder.leaf_cert(parent=root)

    # CRL signed by root but with mismatched issuer name
    crl = builder.crl(
        signer=root,
        issuer=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fake Issuer")]),
        revoked=[
            x509.RevokedCertificateBuilder()
            .serial_number(leaf.cert.serial_number)
            .revocation_date(validation_time - timedelta(days=1))
            .build()
        ],
    )

    builder.features([Feature.has_crl]).server_validation().trusted_certs(root).peer_certificate(
        leaf
    ).expected_peer_name(models.PeerName(kind=PeerKind.DNS, value="example.com")).crls(
        crl
    ).validation_time(validation_time).fails()
