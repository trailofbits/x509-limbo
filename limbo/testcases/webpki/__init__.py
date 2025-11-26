"""
Web PKI (CABF) profile tests.
"""

from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

from limbo.assets import ASSETS_PATH, Certificate, ext
from limbo.models import Feature, KeyUsage, PeerName
from limbo.testcases._core import Builder, testcase

from .aki import *  # noqa: F403
from .cn import *  # noqa: F403
from .eku import *  # noqa: F403
from .nc import *  # noqa: F403
from .san import *  # noqa: F403


@testcase
def explicit_curve(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    Both root and EE convey EC keys using the "explicit" curve encoding,
    which is forbidden under CABF 7.1.3.1.2:

    > The CA SHALL indicate an ECDSA key using the id‐ecPublicKey
    > (OID: 1.2.840.10045.2.1) algorithm identifier. The parameters MUST use
    > the namedCurve encoding.
    """

    root_pem = ASSETS_PATH / "explicit_curve_ca.pem"
    leaf_pem = ASSETS_PATH / "explicit_curve_leaf.pem"

    root = Certificate(x509.load_pem_x509_certificate(root_pem.read_bytes()))
    leaf = Certificate(x509.load_pem_x509_certificate(leaf_pem.read_bytes()))

    builder = (
        builder.server_validation()
        .validation_time(datetime.fromisoformat("2024-03-13T00:00:00Z"))
        .trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="example.com"))
        .fails()
    )


@testcase
def cryptographydotio_chain(builder: Builder) -> None:
    """
    Verifies against a saved copy of `cryptography.io`'s chain. This should
    trivially succeed.
    """
    chain_path = ASSETS_PATH / "cryptography.io.pem"
    chain = [Certificate(c) for c in x509.load_pem_x509_certificates(chain_path.read_bytes())]

    leaf, root = chain.pop(0), chain.pop(-1)
    builder = builder.server_validation().validation_time(
        datetime.fromisoformat("2023-07-10T00:00:00Z")
    )
    builder = (
        builder.trusted_certs(root)
        .peer_certificate(leaf)
        .untrusted_intermediates(*chain)
        .expected_peer_name(PeerName(kind="DNS", value="cryptography.io"))
        .key_usage([KeyUsage.digital_signature])
    ).succeeds()


@testcase
def cryptographydotio_chain_missing_intermediate(builder: Builder) -> None:
    """
    Verifies against a saved copy of `cryptography.io`'s chain, but without its
    intermediates. This should trivially fail.
    """
    chain_path = ASSETS_PATH / "cryptography.io.pem"
    chain = [Certificate(c) for c in x509.load_pem_x509_certificates(chain_path.read_bytes())]

    leaf, root = chain.pop(0), chain.pop(-1)
    builder = builder.server_validation().validation_time(
        datetime.fromisoformat("2023-07-10T00:00:00Z")
    )
    builder = (
        builder.trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="cryptography.io"))
        .key_usage([KeyUsage.digital_signature])
    ).fails()


@testcase
def malformed_aia(builder: Builder) -> None:
    """
    Produces a chain with an EE cert.

    This EE cert contains an Authority Information Access extension with malformed
    contents. This is **invalid** per CABF.

    > The AuthorityInfoAccessSyntax MUST contain one or more AccessDescriptions.
    """
    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("example.com")]),
            critical=False,
        ),
        extra_extension=ext(
            x509.UnrecognizedExtension(x509.OID_AUTHORITY_INFORMATION_ACCESS, b"malformed"),
            critical=False,
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def forbidden_p192_root(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The root cert conveys a P-192 key and signs for the EE with it,
    which is not permitted under the CABF's key or signature types.
    """

    root_key = ec.generate_private_key(ec.SECP192R1())
    root = builder.root_ca(key=root_key)

    leaf = builder.leaf_cert(root)

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def forbidden_p192_leaf(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The EE cert conveys a P-192 key, which is not one of the permitted
    public keys under CABF.
    """

    root = builder.root_ca()

    leaf_key = ec.generate_private_key(ec.SECP192R1())
    leaf = builder.leaf_cert(root, key=leaf_key)

    builder = builder.server_validation().features([Feature.pedantic_webpki_subscriber_key])
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def forbidden_dsa_root(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The root cert conveys a DSA-30272 key and signs for the EE with it,
    which is not permitted under the CABF's key or signature types.
    """

    root_key = dsa.generate_private_key(key_size=3072)
    root = builder.root_ca(key=root_key)

    leaf = builder.leaf_cert(root)

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def forbidden_dsa_leaf(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The EE cert conveys a DSA key, which is not one of the permitted
    public keys under CABF.
    """

    root = builder.root_ca()

    leaf_key = dsa.generate_private_key(3072)
    leaf = builder.leaf_cert(root, key=leaf_key)

    builder = builder.server_validation().features([Feature.pedantic_webpki_subscriber_key])
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def forbidden_weak_rsa_key_in_root(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The root cert is signed with and conveys an RSA-1024 key, which is
    below the security margin (2048) required under CABF 6.1.5.
    """

    root_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    root = builder.root_ca(key=root_key)
    leaf = builder.leaf_cert(root)

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def forbidden_weak_rsa_in_leaf(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The EE cert conveys an RSA 1024 key, which is below the security margin
    (2048) required under CABF 6.1.5.
    """

    root = builder.root_ca()

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    leaf = builder.leaf_cert(root, key=leaf_key)

    builder = builder.server_validation().features([Feature.pedantic_webpki_subscriber_key])
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def forbidden_rsa_not_divisable_by_8_in_root(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The root cert is signed with and conveys an RSA-2052 key, which is
    above the security margin (2048) but not divisible by 8, as is required
    under CABF 6.1.5.
    """

    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2052)
    root = builder.root_ca(key=root_key)
    leaf = builder.leaf_cert(root)

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def forbidden_rsa_key_not_divisable_by_8_in_leaf(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The EE cert conveys an RSA-2052 key, which is above the security margin
    (2048) but not divisible by 8, as is required under CABF 6.1.5.
    """

    root = builder.root_ca()

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2052)
    leaf = builder.leaf_cert(root, key=leaf_key)

    builder = builder.server_validation().features([Feature.pedantic_webpki_subscriber_key])
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def v1_cert(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    This chain is correctly constructed, but the EE cert is marked with
    version 2 (ordinal 1) rather than version 3 (ordinal 2). This is invalid,
    per CABF 7.1.1:

    > Certificates MUST be of type X.509 v3.
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(root, unchecked_version=x509.Version.v1, no_extensions=True)

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def ee_basicconstraints_ca(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The EE certificate has `keyUsage.keyCertSign=FALSE` but
    `basicConstraints.cA=TRUE`, which is explicitly forbidden under
    CABF 7.1.2.7.8:

    > cA MUST be FALSE
    """

    # NOTE: This behavior is implied by RFC 5280, but is only made explicit
    # in the CABF BRs. In 5280, the only requirement is that `keyUsage.keyCertSign`
    # implies `basicConstraints.cA`, not the other way around.

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root, basic_constraints=ext(x509.BasicConstraints(True, None), critical=True)
    )

    builder.server_validation().trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def ca_as_leaf(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> ICA
    ```

    The ICA is in leaf position, despite being a CA certificate,
    which is explicitly forbidden under CABF 7.1.2.7.11 (`keyUsage.keyCertSign` must NOT be
    permitted) and 7.1.2.7.8 (`basicConstraints.cA` MUST be false).
    """

    root = builder.root_ca()
    ica_leaf = builder.intermediate_ca(
        root, san=ext(x509.SubjectAlternativeName([x509.DNSName("ca.example.com")]), critical=False)
    )

    builder = (
        builder.conflicts_with("rfc5280::ca-as-leaf")
        .server_validation()
        .trusted_certs(root)
        .peer_certificate(ica_leaf)
        .expected_peer_name(PeerName(kind="DNS", value="ca.example.com"))
        .fails()
    )
