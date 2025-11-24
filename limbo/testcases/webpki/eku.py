"""
Web PKI Extended Key Usage (EKU) tests.
"""

from cryptography import x509

from limbo.assets import ext
from limbo.models import Feature, KnownEKUs, PeerName
from limbo.testcases._core import Builder, testcase


@testcase
def ee_anyeku(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    This chain is correctly constructed, but the EE cert contains an
    Extended Key Usage extension that contains `anyExtendedKeyUsage`,
    which is explicitly forbidden under CABF 7.1.2.7.10.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        eku=ext(
            x509.ExtendedKeyUsage(
                [x509.OID_SERVER_AUTH, x509.ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE]
            ),
            critical=False,
        ),
    )

    # NOTE: Marked as pedantic since most implementations don't seem to care.
    builder = builder.server_validation().features([Feature.pedantic_webpki_eku])
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).extended_key_usage([KnownEKUs.server_auth]).fails()


@testcase
def ee_critical_eku(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    This chain is correctly constructed, but the EE has an extKeyUsage extension
    marked as critical, which is forbidden per CABF 7.1.2.7.6.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        eku=ext(
            x509.ExtendedKeyUsage([x509.OID_SERVER_AUTH]),
            critical=True,
        ),
    )

    builder = (
        builder.features([Feature.pedantic_webpki_eku])
        .server_validation()
        .trusted_certs(root)
        .peer_certificate(leaf)
        .extended_key_usage([KnownEKUs.server_auth])
        .fails()
    )


@testcase
def ee_without_eku(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    This chain is correctly constructed, but the EE does not have
    the extKeyUsage extension, which is required per CABF 7.1.2.7.6.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(root, eku=None)

    builder = (
        builder.conflicts_with("rfc5280::eku::ee-without-eku")
        .features([Feature.pedantic_webpki_eku])
        .server_validation()
        .trusted_certs(root)
        .peer_certificate(leaf)
        .fails()
    )


@testcase
def root_has_eku(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The root cert includes the extKeyUsage extension, which is forbidden
    under CABF:

    > 7.1.2.1.2 Root CA Extensions
    > Extension     Presence        Critical
    > ...
    > extKeyUsage   MUST NOT        N
    """

    root = builder.root_ca(
        extra_extension=ext(x509.ExtendedKeyUsage([x509.OID_SERVER_AUTH]), critical=False)
    )
    leaf = builder.leaf_cert(root)

    builder = builder.server_validation().features([Feature.pedantic_webpki_eku])
    builder = (
        builder.trusted_certs(root)
        .extended_key_usage([KnownEKUs.server_auth])
        .peer_certificate(leaf)
        .fails()
    )


@testcase
def ca_without_serverauth_issuing_tls(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> ICA (with clientAuth EKU only) -> EE
    ```

    The intermediate CA contains an Extended Key Usage extension with only
    clientAuth, lacking the required serverAuth OID. Per CABF 7.1.2.10.6,
    when a CA certificate includes the EKU extension and issues TLS server
    certificates, it MUST include id-kp-serverAuth.
    """

    root = builder.root_ca()

    # Create intermediate CA with only clientAuth EKU
    intermediate = builder.intermediate_ca(
        root,
        subject=x509.Name.from_rfc4514_string("CN=x509-limbo-intermediate"),
        extra_extension=ext(
            x509.ExtendedKeyUsage([x509.OID_CLIENT_AUTH]),
            critical=False,
        ),
    )

    # Create leaf certificate intended for serverAuth
    leaf = builder.leaf_cert(
        intermediate,
        eku=ext(
            x509.ExtendedKeyUsage([x509.OID_SERVER_AUTH]),
            critical=False,
        ),
    )

    builder = builder.server_validation().features([Feature.pedantic_webpki_eku])
    builder.trusted_certs(root).untrusted_intermediates(intermediate).peer_certificate(
        leaf
    ).expected_peer_name(PeerName(kind="DNS", value="example.com")).extended_key_usage(
        [KnownEKUs.server_auth]
    ).fails()


@testcase
def ca_clientauth_only_issuing_serverauth(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> ICA (with clientAuth EKU only) -> EE (with serverAuth)
    ```

    The intermediate CA has an EKU extension with only clientAuth, but
    issues a certificate with serverAuth. This violates CABF 7.1.2.10.6
    which requires CAs issuing TLS certificates to include serverAuth
    in their EKU if they have an EKU extension.
    """

    root = builder.root_ca()

    # Create intermediate CA with only clientAuth EKU
    intermediate = builder.intermediate_ca(
        root,
        subject=x509.Name.from_rfc4514_string("CN=x509-limbo-intermediate-clientauth"),
        extra_extension=ext(
            x509.ExtendedKeyUsage([x509.OID_CLIENT_AUTH]),
            critical=False,
        ),
    )

    # Create leaf certificate with serverAuth
    leaf = builder.leaf_cert(
        intermediate,
        eku=ext(
            x509.ExtendedKeyUsage([x509.OID_SERVER_AUTH]),
            critical=False,
        ),
    )

    builder = builder.server_validation().features([Feature.pedantic_webpki_eku])
    builder.trusted_certs(root).untrusted_intermediates(intermediate).peer_certificate(
        leaf
    ).expected_peer_name(PeerName(kind="DNS", value="example.com")).extended_key_usage(
        [KnownEKUs.server_auth]
    ).fails()


@testcase
def ca_with_precertificate_oid(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> ICA (with precertificate OID) -> EE
    ```

    The intermediate CA contains the precertificate signing OID
    (1.3.6.1.4.1.11129.2.4.4) in its EKU extension, which is prohibited
    for CA certificates per CABF requirements. This OID should only
    appear in dedicated precertificate signing certificates.
    """

    precertificate_oid = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.4")

    root = builder.root_ca()

    # Create intermediate CA with precertificate OID
    intermediate = builder.intermediate_ca(
        root,
        subject=x509.Name.from_rfc4514_string("CN=x509-limbo-intermediate-precert"),
        extra_extension=ext(
            x509.ExtendedKeyUsage([precertificate_oid]),
            critical=False,
        ),
    )

    # Create normal leaf certificate
    leaf = builder.leaf_cert(intermediate)

    builder = builder.server_validation().features([Feature.pedantic_webpki_eku])
    builder.trusted_certs(root).untrusted_intermediates(intermediate).peer_certificate(
        leaf
    ).expected_peer_name(PeerName(kind="DNS", value="example.com")).extended_key_usage(
        [KnownEKUs.server_auth]
    ).fails()


@testcase
def ca_with_serverauth_and_precertificate(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> ICA (with serverAuth and precertificate OID) -> EE
    ```

    The intermediate CA contains both serverAuth and the precertificate
    signing OID (1.3.6.1.4.1.11129.2.4.4) in its EKU extension. Even though
    serverAuth is present, the precertificate OID is still prohibited for
    CA certificates per CABF requirements.
    """

    precertificate_oid = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.4")

    root = builder.root_ca()

    # Create intermediate CA with both serverAuth and precertificate OID
    intermediate = builder.intermediate_ca(
        root,
        subject=x509.Name.from_rfc4514_string("CN=x509-limbo-intermediate-mixed"),
        extra_extension=ext(
            x509.ExtendedKeyUsage([x509.OID_SERVER_AUTH, precertificate_oid]),
            critical=False,
        ),
    )

    # Create leaf certificate
    leaf = builder.leaf_cert(intermediate)

    builder = builder.server_validation().features([Feature.pedantic_webpki_eku])
    builder.trusted_certs(root).untrusted_intermediates(intermediate).peer_certificate(
        leaf
    ).expected_peer_name(PeerName(kind="DNS", value="example.com")).extended_key_usage(
        [KnownEKUs.server_auth]
    ).fails()


@testcase
def unrestricted_ca_issuing_serverauth(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> ICA (no EKU) -> EE (with serverAuth)
    ```

    The intermediate CA has no EKU extension, which means it's unrestricted
    and can issue certificates for any purpose. This is valid per CABF
    requirements - CAs without EKU can issue any type of certificate.
    """

    root = builder.root_ca()

    # Create intermediate CA without EKU extension (unrestricted)
    intermediate = builder.intermediate_ca(
        root,
        subject=x509.Name.from_rfc4514_string("CN=x509-limbo-intermediate-unrestricted"),
    )

    # Create leaf certificate with serverAuth
    leaf = builder.leaf_cert(
        intermediate,
        eku=ext(
            x509.ExtendedKeyUsage([x509.OID_SERVER_AUTH]),
            critical=False,
        ),
    )

    builder = builder.server_validation().features([Feature.pedantic_webpki_eku])
    builder.trusted_certs(root).untrusted_intermediates(intermediate).peer_certificate(
        leaf
    ).expected_peer_name(PeerName(kind="DNS", value="example.com")).extended_key_usage(
        [KnownEKUs.server_auth]
    ).succeeds()


@testcase
def ca_with_serverauth_issuing_matching(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> ICA (with serverAuth EKU) -> EE (with serverAuth)
    ```

    The intermediate CA has an EKU extension with serverAuth and issues
    a certificate with serverAuth. This is valid per CABF 7.1.2.10.6
    as the CA includes the required serverAuth OID when issuing TLS
    certificates.
    """

    root = builder.root_ca()

    # Create intermediate CA with serverAuth EKU
    intermediate = builder.intermediate_ca(
        root,
        subject=x509.Name.from_rfc4514_string("CN=x509-limbo-intermediate-serverauth"),
        extra_extension=ext(
            x509.ExtendedKeyUsage([x509.OID_SERVER_AUTH]),
            critical=False,
        ),
    )

    # Create leaf certificate with serverAuth
    leaf = builder.leaf_cert(
        intermediate,
        eku=ext(
            x509.ExtendedKeyUsage([x509.OID_SERVER_AUTH]),
            critical=False,
        ),
    )

    builder = builder.server_validation().features([Feature.pedantic_webpki_eku])
    builder.trusted_certs(root).untrusted_intermediates(intermediate).peer_certificate(
        leaf
    ).expected_peer_name(PeerName(kind="DNS", value="example.com")).extended_key_usage(
        [KnownEKUs.server_auth]
    ).succeeds()
