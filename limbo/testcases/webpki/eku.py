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
    clientAuth, lacking the required serverAuth OID.

    > CABF 7.1.2.10.6 CA Certificate Extended Key Usage:
    > id-kp-serverAuth (1.3.6.1.5.5.7.3.1): MUST
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
def ca_with_precertificate_oid(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> ICA (with precertificate OID) -> EE
    ```

    The intermediate CA contains the precertificate signing OID
    (1.3.6.1.4.1.11129.2.4.4) in its EKU extension.

    > CABF 7.1.2.10.6 CA Certificate Extended Key Usage:
    > Precertificate Signing Certificate (1.3.6.1.4.1.11129.2.4.4): MUST NOT
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
    serverAuth is present, the precertificate OID is still prohibited.

    > CABF 7.1.2.10.6 CA Certificate Extended Key Usage:
    > Precertificate Signing Certificate (1.3.6.1.4.1.11129.2.4.4): MUST NOT
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
    and can issue certificates for any purpose. CABF 7.1.2.10.6 requirements
    only apply when the EKU extension is present.
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
    a certificate with serverAuth. The CA includes the required serverAuth OID.

    > CABF 7.1.2.10.6 CA Certificate Extended Key Usage:
    > id-kp-serverAuth (1.3.6.1.5.5.7.3.1): MUST
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


@testcase
def ca_with_codesigning_eku(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> ICA (with serverAuth and codeSigning EKU) -> EE
    ```

    The intermediate CA contains the codeSigning OID (1.3.6.1.5.5.7.3.3)
    in its EKU extension, which is prohibited for CA certificates.

    > CABF 7.1.2.10.6 CA Certificate Extended Key Usage:
    > id-kp-codeSigning (1.3.6.1.5.5.7.3.3): MUST NOT
    """

    root = builder.root_ca()

    # Create intermediate CA with serverAuth and codeSigning EKU
    intermediate = builder.intermediate_ca(
        root,
        subject=x509.Name.from_rfc4514_string("CN=x509-limbo-intermediate-codesigning"),
        extra_extension=ext(
            x509.ExtendedKeyUsage([x509.OID_SERVER_AUTH, x509.OID_CODE_SIGNING]),
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
def ca_with_emailprotection_eku(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> ICA (with serverAuth and emailProtection EKU) -> EE
    ```

    The intermediate CA contains the emailProtection OID (1.3.6.1.5.5.7.3.4)
    in its EKU extension, which is prohibited for CA certificates.

    > CABF 7.1.2.10.6 CA Certificate Extended Key Usage:
    > id-kp-emailProtection (1.3.6.1.5.5.7.3.4): MUST NOT
    """

    root = builder.root_ca()

    # Create intermediate CA with serverAuth and emailProtection EKU
    intermediate = builder.intermediate_ca(
        root,
        subject=x509.Name.from_rfc4514_string("CN=x509-limbo-intermediate-emailprotection"),
        extra_extension=ext(
            x509.ExtendedKeyUsage([x509.OID_SERVER_AUTH, x509.OID_EMAIL_PROTECTION]),
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
def ca_with_timestamping_eku(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> ICA (with serverAuth and timeStamping EKU) -> EE
    ```

    The intermediate CA contains the timeStamping OID (1.3.6.1.5.5.7.3.8)
    in its EKU extension, which is prohibited for CA certificates.

    > CABF 7.1.2.10.6 CA Certificate Extended Key Usage:
    > id-kp-timeStamping (1.3.6.1.5.5.7.3.8): MUST NOT
    """

    root = builder.root_ca()

    # Create intermediate CA with serverAuth and timeStamping EKU
    intermediate = builder.intermediate_ca(
        root,
        subject=x509.Name.from_rfc4514_string("CN=x509-limbo-intermediate-timestamping"),
        extra_extension=ext(
            x509.ExtendedKeyUsage([x509.OID_SERVER_AUTH, x509.OID_TIME_STAMPING]),
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
def ca_with_ocspsigning_eku(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> ICA (with serverAuth and OCSPSigning EKU) -> EE
    ```

    The intermediate CA contains the OCSPSigning OID (1.3.6.1.5.5.7.3.9)
    in its EKU extension, which is prohibited for CA certificates.

    > CABF 7.1.2.10.6 CA Certificate Extended Key Usage:
    > id-kp-OCSPSigning (1.3.6.1.5.5.7.3.9): MUST NOT
    """

    root = builder.root_ca()

    # Create intermediate CA with serverAuth and OCSPSigning EKU
    intermediate = builder.intermediate_ca(
        root,
        subject=x509.Name.from_rfc4514_string("CN=x509-limbo-intermediate-ocspsigning"),
        extra_extension=ext(
            x509.ExtendedKeyUsage([x509.OID_SERVER_AUTH, x509.OID_OCSP_SIGNING]),
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
def ca_with_anyeku(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> ICA (with serverAuth and anyExtendedKeyUsage) -> EE
    ```

    The intermediate CA contains the anyExtendedKeyUsage OID (2.5.29.37.0)
    in its EKU extension, which is prohibited for CA certificates.

    > CABF 7.1.2.10.6 CA Certificate Extended Key Usage:
    > anyExtendedKeyUsage (2.5.29.37.0): MUST NOT
    """

    root = builder.root_ca()

    # Create intermediate CA with serverAuth and anyExtendedKeyUsage
    intermediate = builder.intermediate_ca(
        root,
        subject=x509.Name.from_rfc4514_string("CN=x509-limbo-intermediate-anyeku"),
        extra_extension=ext(
            x509.ExtendedKeyUsage(
                [x509.OID_SERVER_AUTH, x509.ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE]
            ),
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
