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
def ee_clientauth_only(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    This chain is correctly constructed, but the EE cert contains an
    Extended Key Usage extension that only contains id-kp-clientAuth,
    missing the required id-kp-serverAuth OID.
    Per CABF BR 7.1.2.7.10, subscriber certificates MUST include
    id-kp-serverAuth (1.3.6.1.5.5.7.3.1).
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        eku=ext(
            x509.ExtendedKeyUsage([x509.OID_CLIENT_AUTH]),
            critical=False,
        ),
    )

    builder = builder.server_validation().features([Feature.pedantic_webpki_eku])
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).extended_key_usage([KnownEKUs.server_auth]).fails()


@testcase
def ee_precertificate_only(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    This chain is correctly constructed, but the EE cert contains an
    Extended Key Usage extension that only contains the Precertificate
    Signing Certificate OID (1.3.6.1.4.1.11129.2.4.4).
    Per CABF BR 7.1.2.7.10, this OID MUST NOT appear in subscriber
    certificates. Per RFC 6962 Section 3.1, this OID is reserved for
    special-purpose CA certificates used in Certificate Transparency.
    """

    # Create the precertificate OID
    precertificate_oid = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.4")

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        eku=ext(
            x509.ExtendedKeyUsage([precertificate_oid]),
            critical=False,
        ),
    )

    builder = builder.server_validation().features([Feature.pedantic_webpki_eku])
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).extended_key_usage([KnownEKUs.server_auth]).fails()


@testcase
def ee_precertificate_with_serverauth(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    This chain is correctly constructed, but the EE cert contains an
    Extended Key Usage extension that includes both id-kp-serverAuth and
    the Precertificate Signing Certificate OID (1.3.6.1.4.1.11129.2.4.4).
    Per CABF BR 7.1.2.7.10, the Precertificate Signing Certificate OID
    MUST NOT appear in subscriber certificates, even when id-kp-serverAuth
    is present. Per RFC 6962 Section 3.1, this OID is reserved for
    special-purpose CA certificates used in Certificate Transparency.
    """

    # Create the precertificate OID
    precertificate_oid = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.4")

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        eku=ext(
            x509.ExtendedKeyUsage([x509.OID_SERVER_AUTH, precertificate_oid]),
            critical=False,
        ),
    )

    builder = builder.server_validation().features([Feature.pedantic_webpki_eku])
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).extended_key_usage([KnownEKUs.server_auth]).fails()


@testcase
def ee_serverauth_with_additional(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> EE
    ```

    This chain is correctly constructed. The EE cert contains an
    Extended Key Usage extension that includes id-kp-serverAuth along with
    id-kp-clientAuth. Per CABF BR 7.1.2.7.10, id-kp-serverAuth MUST be
    present and id-kp-clientAuth MAY be present, so this combination is valid.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        eku=ext(
            x509.ExtendedKeyUsage([x509.OID_SERVER_AUTH, x509.OID_CLIENT_AUTH]),
            critical=False,
        ),
    )

    builder = builder.server_validation().features([Feature.pedantic_webpki_eku])
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).extended_key_usage([KnownEKUs.server_auth]).succeeds()


@testcase
def ee_codesigning_with_serverauth(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    This chain is correctly constructed, but the EE cert contains an
    Extended Key Usage extension that includes both id-kp-serverAuth and
    id-kp-codeSigning (1.3.6.1.5.5.7.3.3).
    Per CABF BR 7.1.2.7.10, id-kp-codeSigning MUST NOT appear in
    subscriber certificates for TLS.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        eku=ext(
            x509.ExtendedKeyUsage([x509.OID_SERVER_AUTH, x509.ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=False,
        ),
    )

    builder = builder.server_validation().features([Feature.pedantic_webpki_eku])
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).extended_key_usage([KnownEKUs.server_auth]).fails()


@testcase
def ee_emailprotection_with_serverauth(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    This chain is correctly constructed, but the EE cert contains an
    Extended Key Usage extension that includes both id-kp-serverAuth and
    id-kp-emailProtection (1.3.6.1.5.5.7.3.4).
    Per CABF BR 7.1.2.7.10, id-kp-emailProtection MUST NOT appear in
    subscriber certificates for TLS.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        eku=ext(
            x509.ExtendedKeyUsage(
                [x509.OID_SERVER_AUTH, x509.ExtendedKeyUsageOID.EMAIL_PROTECTION]
            ),
            critical=False,
        ),
    )

    builder = builder.server_validation().features([Feature.pedantic_webpki_eku])
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).extended_key_usage([KnownEKUs.server_auth]).fails()


@testcase
def ee_timestamping_with_serverauth(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    This chain is correctly constructed, but the EE cert contains an
    Extended Key Usage extension that includes both id-kp-serverAuth and
    id-kp-timeStamping (1.3.6.1.5.5.7.3.8).
    Per CABF BR 7.1.2.7.10, id-kp-timeStamping MUST NOT appear in
    subscriber certificates for TLS.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        eku=ext(
            x509.ExtendedKeyUsage([x509.OID_SERVER_AUTH, x509.ExtendedKeyUsageOID.TIME_STAMPING]),
            critical=False,
        ),
    )

    builder = builder.server_validation().features([Feature.pedantic_webpki_eku])
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).extended_key_usage([KnownEKUs.server_auth]).fails()


@testcase
def ee_ocspsigning_with_serverauth(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    This chain is correctly constructed, but the EE cert contains an
    Extended Key Usage extension that includes both id-kp-serverAuth and
    id-kp-OCSPSigning (1.3.6.1.5.5.7.3.9).
    Per CABF BR 7.1.2.7.10, id-kp-OCSPSigning MUST NOT appear in
    subscriber certificates for TLS.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        eku=ext(
            x509.ExtendedKeyUsage([x509.OID_SERVER_AUTH, x509.ExtendedKeyUsageOID.OCSP_SIGNING]),
            critical=False,
        ),
    )

    builder = builder.server_validation().features([Feature.pedantic_webpki_eku])
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).extended_key_usage([KnownEKUs.server_auth]).fails()
