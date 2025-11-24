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
    Extended Key Usage extension that only contains clientAuth,
    missing the required serverAuth OID per CABF requirements.
    Subscriber certificates MUST include id-kp-serverAuth (1.3.6.1.5.5.7.3.1).
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
    Extended Key Usage extension that only contains the precertificate
    signing OID (1.3.6.1.4.1.11129.2.4.4), which is prohibited in
    production certificates per CABF requirements.
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
    Extended Key Usage extension that includes both serverAuth and
    the precertificate signing OID (1.3.6.1.4.1.11129.2.4.4).
    The precertificate OID is prohibited in production certificates
    per CABF requirements, even when serverAuth is present.
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
    Extended Key Usage extension that includes serverAuth along with
    additional valid purposes (clientAuth in this case).
    This is valid per CABF requirements as long as serverAuth is present
    and no prohibited OIDs are included.
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
