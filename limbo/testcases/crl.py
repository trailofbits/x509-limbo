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
def issuer_missing_crlsign(builder: Builder) -> None:
    """
    Tests CRL validation when the CA issuer has a keyUsage extension with only
    `keyCertSign` set (no `cRLSign`).

    Per RFC 5280 Section 4.2.1.3, if the keyUsage extension is present in a CA
    certificate, the `cRLSign` bit MUST be set if the CA will be issuing CRLs.
    A CRL signed by a CA without the `cRLSign` bit should be rejected.
    """
    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca(
        key_usage=ext(
            x509.KeyUsage(
                digital_signature=False,
                key_cert_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=False,
        ),
    )

    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "issuer-missing-crlsign.example.com"),
            ]
        ),
        eku=ext(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False),
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("issuer-missing-crlsign.example.com")]),
            critical=False,
        ),
    )

    crl = builder.crl(
        signer=root,
        revoked=[
            # Revoke a random certificate, not the leaf, to ensure failure is due
            # to issuer authorization, not revocation status.
            x509.RevokedCertificateBuilder()
            .serial_number(x509.random_serial_number())
            .revocation_date(validation_time - timedelta(days=1))
            .build()
        ],
    )

    builder.features([Feature.has_crl]).importance(
        Importance.HIGH
    ).server_validation().trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        models.PeerName(kind=PeerKind.DNS, value="issuer-missing-crlsign.example.com")
    ).crls(crl).validation_time(validation_time).fails()


@testcase
def issuer_keyusage_crlsign_false(builder: Builder) -> None:
    """
    Tests CRL validation when the CA issuer has a keyUsage extension with
    `cRLSign` explicitly set to FALSE.

    Per RFC 5280 Section 4.2.1.3, if the keyUsage extension is present in a CA
    certificate, the `cRLSign` bit MUST be set if the CA will be issuing CRLs.
    A CRL signed by a CA with `cRLSign=FALSE` should be rejected.
    """
    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca(
        key_usage=ext(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=False,
        ),
    )

    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "issuer-crlsign-false.example.com"),
            ]
        ),
        eku=ext(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False),
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("issuer-crlsign-false.example.com")]),
            critical=False,
        ),
    )

    crl = builder.crl(
        signer=root,
        revoked=[
            # Revoke a random certificate, not the leaf, to ensure failure is due
            # to issuer authorization, not revocation status.
            x509.RevokedCertificateBuilder()
            .serial_number(x509.random_serial_number())
            .revocation_date(validation_time - timedelta(days=1))
            .build()
        ],
    )

    builder.features([Feature.has_crl]).importance(
        Importance.HIGH
    ).server_validation().trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        models.PeerName(kind=PeerKind.DNS, value="issuer-crlsign-false.example.com")
    ).crls(crl).validation_time(validation_time).fails()


@testcase
def issuer_no_keyusage_extension(builder: Builder) -> None:
    """
    Tests CRL validation when the CA issuer has no keyUsage extension.

    Per RFC 5280 Section 6.3.3(f), the CRL validation algorithm states:
    "If a key usage extension is present in the CRL issuer's certificate,
    verify that the cRLSign bit is set." This conditional check means that
    when keyUsage is absent, there is no cRLSign verification to perform.

    Note: RFC 5280 Section 4.2.1.3 states that "Conforming CAs MUST include
    this extension in certificates that contain public keys that are used to
    validate digital signatures on other public key certificates or CRLs."
    However, this is a certificate issuance requirement, not a validation
    requirement. The validation algorithm in Section 6.3.3(f) explicitly uses
    conditional language ("If... is present").
    """
    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca(
        key_usage=None,
    )

    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "issuer-no-keyusage.example.com"),
            ]
        ),
        eku=ext(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False),
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("issuer-no-keyusage.example.com")]),
            critical=False,
        ),
    )

    crl = builder.crl(
        signer=root,
        revoked=[
            # Revoke a random certificate, not the leaf.
            x509.RevokedCertificateBuilder()
            .serial_number(x509.random_serial_number())
            .revocation_date(validation_time - timedelta(days=1))
            .build()
        ],
    )

    builder.features([Feature.has_crl]).importance(
        Importance.HIGH
    ).server_validation().trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        models.PeerName(kind=PeerKind.DNS, value="issuer-no-keyusage.example.com")
    ).crls(crl).validation_time(validation_time).succeeds()


@testcase
def issuer_valid_crlsign_and_keycertsign(builder: Builder) -> None:
    """
    Tests CRL validation when the CA issuer has a keyUsage extension with both
    `keyCertSign` and `cRLSign` bits set.

    This is the standard configuration for a CA that issues both certificates
    and CRLs. The CRL should be accepted.
    """
    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    root = builder.root_ca(
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

    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "issuer-valid-crlsign.example.com"),
            ]
        ),
        eku=ext(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False),
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("issuer-valid-crlsign.example.com")]),
            critical=False,
        ),
    )

    crl = builder.crl(
        signer=root,
        revoked=[
            # Revoke a random certificate, not the leaf.
            x509.RevokedCertificateBuilder()
            .serial_number(x509.random_serial_number())
            .revocation_date(validation_time - timedelta(days=1))
            .build()
        ],
    )

    builder.features([Feature.has_crl]).importance(
        Importance.HIGH
    ).server_validation().trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        models.PeerName(kind=PeerKind.DNS, value="issuer-valid-crlsign.example.com")
    ).crls(crl).validation_time(validation_time).succeeds()


@testcase
def issuer_only_crlsign(builder: Builder) -> None:
    """
    Tests CRL validation when the CA issuer has a keyUsage extension with only
    `cRLSign` set (no `keyCertSign`).

    This tests a CA that is authorized only for CRL signing. This is unusual
    but valid - a CA could delegate CRL signing to a separate key.
    The CRL should be accepted since the `cRLSign` bit is properly set.
    """
    validation_time = datetime.fromisoformat("2024-01-01T00:00:00Z")

    # Create a root CA with only cRLSign (no keyCertSign)
    # This CA can sign CRLs but not certificates
    root = builder.root_ca(
        key_usage=ext(
            x509.KeyUsage(
                digital_signature=False,
                key_cert_sign=False,
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

    # Note: The leaf is still signed by this root even though it lacks keyCertSign.
    # This creates an invalid cert chain, but we're testing CRL validation, not
    # certificate chain validation. The test focuses on whether the CRL issuer
    # is authorized to sign CRLs.
    leaf = builder.leaf_cert(
        parent=root,
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "issuer-only-crlsign.example.com"),
            ]
        ),
        eku=ext(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False),
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("issuer-only-crlsign.example.com")]),
            critical=False,
        ),
    )

    crl = builder.crl(
        signer=root,
        revoked=[
            # Revoke a random certificate, not the leaf.
            x509.RevokedCertificateBuilder()
            .serial_number(x509.random_serial_number())
            .revocation_date(validation_time - timedelta(days=1))
            .build()
        ],
    )

    # This test expects failure because the root CA lacks keyCertSign,
    # making the certificate chain itself invalid (not just the CRL validation).
    builder.features([Feature.has_crl]).importance(
        Importance.HIGH
    ).server_validation().trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        models.PeerName(kind=PeerKind.DNS, value="issuer-only-crlsign.example.com")
    ).crls(crl).validation_time(validation_time).fails()
