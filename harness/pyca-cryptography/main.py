import ipaddress
import sys

from cryptography import __version__ as pyca_version
from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from limbo.models import (
    ActualResult,
    Feature,
    KnownEKUs,
    Limbo,
    LimboResult,
    PeerKind,
    PeerName,
    Testcase,
    TestcaseResult,
    ValidationKind,
)

LIMBO_UNSUPPORTED_FEATURES = {
    # NOTE: Path validation is required to reject wildcards on public suffixes,
    # however this isn't practical and most implementations make no attempt to
    # comply with this.
    Feature.pedantic_public_suffix_wildcard,
    # TODO: We don't support Distinguished Name Constraints yet.
    Feature.name_constraint_dn,
    # Our support for custom EKUs is limited, and we (like most impls.) don't
    # handle all EKU conditions under CABF.
    Feature.pedantic_webpki_eku,
    # Most CABF validators do not enforce the CABF key requirements on
    # subscriber keys (i.e., in the leaf certificate).
    Feature.pedantic_webpki_subscriber_key,
    # Tests that fail based on a strict reading of RFC 5280
    # but are widely ignored by validators.
    Feature.pedantic_rfc5280,
    # In rare circumstances, CABF relaxes RFC 5280's prescriptions in
    # incompatible ways. Our validator always tries (by default) to comply
    # closer to CABF, so we skip these.
    Feature.rfc5280_incompatible_with_webpki,
    # We do not support policy constraints.
    Feature.has_policy_constraints,
    # We do not support CRLs
    Feature.has_crl,
}

LIMBO_SKIP_TESTCASES = {
    # We unconditionally count intermediate certificates for pathlen and max
    # depth constraint purposes, even when self-issued.
    # This is a violation of RFC 5280, but is consistent with Go's crypto/x509
    # and Rust's webpki crate do.
    "pathlen::self-issued-certs-pathlen",
    "pathlen::max-chain-depth-1-self-issued",
    # We allow certificates with serial numbers of zero. This is
    # invalid under RFC 5280 but is widely violated by certs in common
    # trust stores.
    "rfc5280::serial::zero",
    # We allow CAs that don't have AKIs, which is forbidden under
    # RFC 5280. This is consistent with what Go's crypto/x509 and Rust's
    # webpki crate do.
    "rfc5280::ski::root-missing-ski",
    "rfc5280::ski::intermediate-missing-ski",
    # We currently allow intermediate CAs that don't have AKIs, which
    # is technically forbidden under CABF. This is consistent with what
    # Go's crypto/x509 and Rust's webpki crate do.
    "rfc5280::aki::intermediate-missing-aki",
    # We allow root CAs where the AKI and SKI mismatch, which is technically
    # forbidden under CABF. This is consistent with what
    # Go's crypto/x509 and Rust's webpki crate do.
    "webpki::aki::root-with-aki-ski-mismatch",
    # We allow RSA keys that aren't divisible by 8, which is technically
    # forbidden under CABF. No other implementation checks this either.
    "webpki::forbidden-rsa-not-divisible-by-8-in-root",
    # We disallow CAs in the leaf position, which is explicitly forbidden
    # by CABF (but implicitly permitted under RFC 5280). This is consistent
    # with what webpki and rustls do, but inconsistent with Go and OpenSSL.
    "rfc5280::ca-as-leaf",
    "pathlen::validation-ignores-pathlen-in-leaf",
}


def _get_limbo_peer(expected_peer: PeerName):
    match expected_peer.kind:
        case PeerKind.DNS:
            return x509.DNSName(expected_peer.value)
        case PeerKind.IP:
            return x509.IPAddress(ipaddress.ip_address(expected_peer.value))
        case _:
            raise ValueError(f"unexpected peer kind: {expected_peer.kind}")


def _skip(tc: Testcase, msg: str) -> TestcaseResult:
    return TestcaseResult(id=tc.id, actual_result=ActualResult.SKIPPED, context=msg)


def evaluate_testcase(testcase: Testcase) -> TestcaseResult:
    if testcase.id in LIMBO_SKIP_TESTCASES:
        return _skip(testcase, "testcase skipped (explicitly unsupported case)")

    if LIMBO_UNSUPPORTED_FEATURES.intersection(testcase.features):
        return _skip(testcase, "testcase skipped (explicit unsupported feature)")

    if testcase.validation_kind != ValidationKind.SERVER:
        return _skip(testcase, "non-SERVER cases not supported yet")

    if testcase.signature_algorithms != []:
        return _skip(testcase, "signature algorithm customization not supported yet")

    if testcase.extended_key_usage not in ([], [KnownEKUs.server_auth]):
        return _skip(testcase, "non-serverAuth EKUs not supported yet")

    trusted_certs = [load_pem_x509_certificate(cert.encode()) for cert in testcase.trusted_certs]
    untrusted_intermediates = [
        load_pem_x509_certificate(cert.encode()) for cert in testcase.untrusted_intermediates
    ]

    peer_certificate = load_pem_x509_certificate(testcase.peer_certificate.encode())
    peer_name = _get_limbo_peer(testcase.expected_peer_name)

    builder = PolicyBuilder().store(Store(trusted_certs))
    if validation_time := testcase.validation_time:
        builder = builder.time(validation_time)

    if testcase.max_chain_depth is not None:
        builder = builder.max_chain_depth(testcase.max_chain_depth)

    # This can fail if the peer name is invalid.
    try:
        verifier = builder.build_server_verifier(peer_name)
    except ValueError as e:
        return TestcaseResult(id=testcase.id, actual_result=ActualResult.FAILURE, context=str(e))

    try:
        verifier.verify(peer_certificate, untrusted_intermediates)
        return TestcaseResult(
            id=testcase.id, actual_result=ActualResult.SUCCESS, context="chain built successfully"
        )
    except VerificationError as e:
        return TestcaseResult(id=testcase.id, actual_result=ActualResult.FAILURE, context=str(e))


def main():
    limbo = Limbo.model_validate_json(sys.stdin.read())

    results: list[TestcaseResult] = []
    for testcase in limbo.testcases:
        results.append(evaluate_testcase(testcase))

    print(
        LimboResult(
            version=1, harness=f"pyca-cryptography-{pyca_version}", results=results
        ).model_dump_json(indent=2)
    )


if __name__ == "__main__":
    main()
