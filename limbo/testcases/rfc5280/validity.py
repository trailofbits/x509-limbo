"""
RFC 5280 validity testcases.
"""

from datetime import datetime, timedelta

from limbo.models import Importance
from limbo.testcases._core import Builder, testcase


@testcase
def expired_root(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> intermediate -> EE
    ```

    All three certificates are well-formed, but the root
    (and only the root) is expired at the validation time.
    """

    # Root is valid from 2016 to 2020.
    root = builder.root_ca(
        not_before=datetime.fromisoformat("2016-01-01T00:00:00Z"),
        not_after=datetime.fromisoformat("2020-01-01T00:00:00Z"),
    )

    # Intermediate is valid from 2016 to 2026.
    intermediate = builder.intermediate_ca(
        root,
        not_before=datetime.fromisoformat("2016-01-01T00:00:00Z"),
        not_after=datetime.fromisoformat("2026-01-01T00:00:00Z"),
    )

    # Leaf is valid from 2018 to 2023.
    leaf = builder.leaf_cert(
        intermediate,
        not_before=datetime.fromisoformat("2018-01-01T00:00:00Z"),
        not_after=datetime.fromisoformat("2023-01-01T00:00:00Z"),
    )

    builder = (
        builder.server_validation()
        .importance(Importance.UNDETERMINED)
        .trusted_certs(root)
        .untrusted_intermediates(intermediate)
        .peer_certificate(leaf)
        # We validate in 2022, which is valid for the intermediate and leaf
        # but not the root.
        .validation_time(datetime.fromisoformat("2022-01-01T00:00:00Z"))
        .fails()
    )


@testcase
def expired_intermediate(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> intermediate -> EE
    ```

    All three certificates are well-formed, but the intermediate
    (and only the intermediate) is expired at the validation time.
    """

    # Root is valid from 2016 to 2026.
    root = builder.root_ca(
        not_before=datetime.fromisoformat("2016-01-01T00:00:00Z"),
        not_after=datetime.fromisoformat("2026-01-01T00:00:00Z"),
    )

    # Intermediate is valid from 2016 to 2020.
    intermediate = builder.intermediate_ca(
        root,
        not_before=datetime.fromisoformat("2016-01-01T00:00:00Z"),
        not_after=datetime.fromisoformat("2020-01-01T00:00:00Z"),
    )

    # Leaf is valid from 2018 to 2023.
    leaf = builder.leaf_cert(
        intermediate,
        not_before=datetime.fromisoformat("2018-01-01T00:00:00Z"),
        not_after=datetime.fromisoformat("2023-01-01T00:00:00Z"),
    )

    builder = (
        builder.server_validation()
        .importance(Importance.CRITICAL)
        .trusted_certs(root)
        .untrusted_intermediates(intermediate)
        .peer_certificate(leaf)
        # We validate in 2022, which is valid for the root and leaf
        # but not the intermediate.
        .validation_time(datetime.fromisoformat("2022-01-01T00:00:00Z"))
        .fails()
    )


@testcase
def expired_leaf(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> intermediate -> EE
    ```

    All three certificates are well-formed, but the leaf
    (and only the leaf) is expired at the validation time.
    """

    # Root is valid from 2016 to 2026.
    root = builder.root_ca(
        not_before=datetime.fromisoformat("2016-01-01T00:00:00Z"),
        not_after=datetime.fromisoformat("2026-01-01T00:00:00Z"),
    )

    # Intermediate is valid from 2016 to 2026.
    intermediate = builder.intermediate_ca(
        root,
        not_before=datetime.fromisoformat("2016-01-01T00:00:00Z"),
        not_after=datetime.fromisoformat("2026-01-01T00:00:00Z"),
    )

    # Leaf is valid from 2018 to 2021.
    leaf = builder.leaf_cert(
        intermediate,
        not_before=datetime.fromisoformat("2018-01-01T00:00:00Z"),
        not_after=datetime.fromisoformat("2021-01-01T00:00:00Z"),
    )

    builder = (
        builder.server_validation()
        .importance(Importance.CRITICAL)
        .trusted_certs(root)
        .untrusted_intermediates(intermediate)
        .peer_certificate(leaf)
        # We validate in 2022, which is valid for the root and intermediate
        # but not the leaf.
        .validation_time(datetime.fromisoformat("2022-01-01T00:00:00Z"))
        .fails()
    )


@testcase
def notbefore_exact(builder: Builder) -> None:
    """
    Produces the following valid chain:

    ```
    root -> ICA -> EE
    ```

    EE becomes valid at `2024-03-01T00:00:00Z`, and the chain is validated at
    exactly `2024-03-01T00:00:00Z`.

    RFC 5280 4.1.2.5 says that `notBefore` is inclusive, so this chain should
    validate:

    > The validity period for a certificate is the period of time from
    > notBefore through notAfter, inclusive.
    """

    not_before = datetime.fromisoformat("2024-03-01T00:00:00Z")
    not_after = datetime.fromisoformat("2024-04-01T00:00:00Z")

    root = builder.root_ca(not_before=not_before, not_after=not_after)
    ica = builder.intermediate_ca(root, not_before=not_before, not_after=not_after)
    leaf = builder.leaf_cert(
        ica,
        not_before=not_before,
        not_after=not_after,
    )

    builder = (
        builder.server_validation()
        .trusted_certs(root)
        .untrusted_intermediates(ica)
        .peer_certificate(leaf)
        .validation_time(not_before)
        .succeeds()
    )


@testcase
def notbefore_fractional(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> ICA -> EE
    ```

    EE becomes valid at `2024-03-01T00:00:01Z`, and the chain is validated at
    exactly `2024-03-01T00:00:00.999Z`.

    This is the counterpart to `rfc5280::validity::notafter-fractional`:
    despite rounding to the `notBefore` date, implementations should
    `floor` the validation time instead and subsequently reject this chain.
    """

    not_before = datetime.fromisoformat("2024-03-01T00:00:01Z")
    not_after = datetime.fromisoformat("2024-04-01T00:00:00Z")

    root = builder.root_ca(not_before=not_before, not_after=not_after)
    ica = builder.intermediate_ca(root, not_before=not_before, not_after=not_after)
    leaf = builder.leaf_cert(
        ica,
        not_before=not_before,
        not_after=not_after,
    )

    builder = (
        builder.server_validation()
        .trusted_certs(root)
        .untrusted_intermediates(ica)
        .peer_certificate(leaf)
        .validation_time(not_before - timedelta(milliseconds=1))
        .fails()
    )


@testcase
def notafter_exact(builder: Builder) -> None:
    """
    Produces the following valid chain:

    ```
    root -> ICA -> EE
    ```

    EE expires at `2024-04-01T00:00:00Z`, and the chain is validated at
    exactly `2024-04-01T00:00:00Z`.

    RFC 5280 4.1.2.5 says that `notAfter` is inclusive, so this chain should
    validate:

    > The validity period for a certificate is the period of time from
    > notBefore through notAfter, inclusive.
    """

    not_before = datetime.fromisoformat("2024-03-01T00:00:00Z")
    not_after = datetime.fromisoformat("2024-04-01T00:00:00Z")

    root = builder.root_ca(not_before=not_before, not_after=not_after)
    ica = builder.intermediate_ca(root, not_before=not_before, not_after=not_after)
    leaf = builder.leaf_cert(
        ica,
        not_before=not_before,
        not_after=not_after,
    )

    builder = (
        builder.server_validation()
        .trusted_certs(root)
        .untrusted_intermediates(ica)
        .peer_certificate(leaf)
        .validation_time(not_after)
        .succeeds()
    )


@testcase
def notafter_fractional(builder: Builder) -> None:
    """
    Produces the following **ambiguous** chain:

    ```
    root -> ICA -> EE
    ```

    EE expires at `2024-04-01T00:00:00Z`, and the chain is validated at
    `2024-04-01T00:00:00.005Z`, i.e. 5 milliseconds after the `notAfter`
    date.

    RFC 5280 only allows second granularities in the validity interval, with
    two conflicting interpretations of how to handle the validity check:

    1. Comparisons are performed at the granularity of the encoded
       representation, i.e. `floor(time)`. Under this interpretation,
       the chain is valid, since the entire millisecond interval `[0, .999...]`
       is truncated to `0`.
    2. Comparisons are instantaneous. Under this interpretation the chain
       is **invalid**, since 5 milliseconds after the `notAfter` is factually
       after the `notAfter`.

    There is no clear "winning" interpretation here, although
    CAs in the Web PKI have filed and handled compliance reports based on
    interpretation (1).

    See also:

    * <https://bugzilla.mozilla.org/show_bug.cgi?id=1715455>
    * <https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/-BogZx_IJyk/m/gHm3l613AgAJ>
    """

    not_before = datetime.fromisoformat("2024-03-01T00:00:00Z")
    not_after = datetime.fromisoformat("2024-04-01T00:00:00Z")

    root = builder.root_ca(not_before=not_before, not_after=not_after)
    ica = builder.intermediate_ca(root, not_before=not_before, not_after=not_after)
    leaf = builder.leaf_cert(
        ica,
        not_before=not_before,
        not_after=not_after,
    )

    builder = (
        builder.server_validation()
        .trusted_certs(root)
        .untrusted_intermediates(ica)
        .peer_certificate(leaf)
        .validation_time(not_after + timedelta(milliseconds=5))
        .succeeds()
    )


@testcase
def expired_1_second(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> ICA -> EE
    ```

    The EE certificate expires at `2024-04-01T00:00:00Z`, and the chain is
    validated at `2024-04-01T00:00:01Z`, i.e. exactly 1 second after expiration.

    Per RFC 5280 4.1.2.5, the validity period is inclusive of both `notBefore`
    and `notAfter`. However, any time strictly after `notAfter` should result
    in validation failure. This test ensures implementations strictly reject
    certificates that have expired, even by a single second.
    """

    not_before = datetime.fromisoformat("2024-03-01T00:00:00Z")
    not_after = datetime.fromisoformat("2024-04-01T00:00:00Z")

    root = builder.root_ca(not_before=not_before, not_after=not_after)
    ica = builder.intermediate_ca(root, not_before=not_before, not_after=not_after)
    leaf = builder.leaf_cert(ica, not_before=not_before, not_after=not_after)

    builder = (
        builder.server_validation()
        .importance(Importance.CRITICAL)
        .trusted_certs(root)
        .untrusted_intermediates(ica)
        .peer_certificate(leaf)
        .validation_time(not_after + timedelta(seconds=1))
        .fails()
    )


@testcase
def expired_5_seconds(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> ICA -> EE
    ```

    The EE certificate expires at `2024-04-01T00:00:00Z`, and the chain is
    validated at `2024-04-01T00:00:05Z`, i.e. 5 seconds after expiration.

    This test ensures implementations strictly reject certificates that have
    expired by a small number of seconds.
    """

    not_before = datetime.fromisoformat("2024-03-01T00:00:00Z")
    not_after = datetime.fromisoformat("2024-04-01T00:00:00Z")

    root = builder.root_ca(not_before=not_before, not_after=not_after)
    ica = builder.intermediate_ca(root, not_before=not_before, not_after=not_after)
    leaf = builder.leaf_cert(ica, not_before=not_before, not_after=not_after)

    builder = (
        builder.server_validation()
        .importance(Importance.CRITICAL)
        .trusted_certs(root)
        .untrusted_intermediates(ica)
        .peer_certificate(leaf)
        .validation_time(not_after + timedelta(seconds=5))
        .fails()
    )


@testcase
def expired_1_minute(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> ICA -> EE
    ```

    The EE certificate expires at `2024-04-01T00:00:00Z`, and the chain is
    validated at `2024-04-01T00:01:00Z`, i.e. 1 minute after expiration.

    This test ensures implementations strictly reject certificates that have
    expired by a small amount of time (sub-minute boundaries).
    """

    not_before = datetime.fromisoformat("2024-03-01T00:00:00Z")
    not_after = datetime.fromisoformat("2024-04-01T00:00:00Z")

    root = builder.root_ca(not_before=not_before, not_after=not_after)
    ica = builder.intermediate_ca(root, not_before=not_before, not_after=not_after)
    leaf = builder.leaf_cert(ica, not_before=not_before, not_after=not_after)

    builder = (
        builder.server_validation()
        .importance(Importance.CRITICAL)
        .trusted_certs(root)
        .untrusted_intermediates(ica)
        .peer_certificate(leaf)
        .validation_time(not_after + timedelta(minutes=1))
        .fails()
    )


@testcase
def not_yet_valid_1_second(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> ICA -> EE
    ```

    The EE certificate becomes valid at `2024-03-01T00:00:01Z`, and the chain
    is validated at `2024-03-01T00:00:00Z`, i.e. 1 second before the certificate
    becomes valid.

    Per RFC 5280 4.1.2.5, the validity period is inclusive of `notBefore`.
    However, any time strictly before `notBefore` should result in validation
    failure. This test ensures implementations strictly reject certificates
    that are not yet valid, even by a single second.
    """

    not_before = datetime.fromisoformat("2024-03-01T00:00:01Z")
    not_after = datetime.fromisoformat("2024-04-01T00:00:00Z")

    root = builder.root_ca(not_before=not_before, not_after=not_after)
    ica = builder.intermediate_ca(root, not_before=not_before, not_after=not_after)
    leaf = builder.leaf_cert(ica, not_before=not_before, not_after=not_after)

    builder = (
        builder.server_validation()
        .importance(Importance.CRITICAL)
        .trusted_certs(root)
        .untrusted_intermediates(ica)
        .peer_certificate(leaf)
        .validation_time(not_before - timedelta(seconds=1))
        .fails()
    )


@testcase
def not_yet_valid_5_seconds(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> ICA -> EE
    ```

    The EE certificate becomes valid at `2024-03-01T00:00:05Z`, and the chain
    is validated at `2024-03-01T00:00:00Z`, i.e. 5 seconds before the certificate
    becomes valid.

    This test ensures implementations strictly reject certificates that are
    not yet valid by a small number of seconds.
    """

    not_before = datetime.fromisoformat("2024-03-01T00:00:05Z")
    not_after = datetime.fromisoformat("2024-04-01T00:00:00Z")

    root = builder.root_ca(not_before=not_before, not_after=not_after)
    ica = builder.intermediate_ca(root, not_before=not_before, not_after=not_after)
    leaf = builder.leaf_cert(ica, not_before=not_before, not_after=not_after)

    builder = (
        builder.server_validation()
        .importance(Importance.CRITICAL)
        .trusted_certs(root)
        .untrusted_intermediates(ica)
        .peer_certificate(leaf)
        .validation_time(not_before - timedelta(seconds=5))
        .fails()
    )
