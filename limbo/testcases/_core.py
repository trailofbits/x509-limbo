from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime
from textwrap import dedent
from typing import Any, Literal, Self

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes

from limbo.assets import (
    EPOCH,
    ONE_THOUSAND_YEARS_OF_TORMENT,
    Certificate,
    CertificatePair,
    RawCertificate,
    RawCertificatePair,
    RawCRL,
    _Extension,
    ext,
)
from limbo.der import modify_certificate, modify_crl
from limbo.models import (
    Feature,
    Importance,
    KeyUsage,
    KnownEKUs,
    PeerName,
    SignatureAlgorithm,
    Testcase,
)

logger = logging.getLogger(__name__)


class Builder:
    def _ca(
        self,
        issuer: x509.Name,
        subject: x509.Name | None,
        serial: int | None,
        not_before: datetime,
        not_after: datetime,
        key: CertificateIssuerPrivateKeyTypes | None,
        basic_constraints: _Extension[x509.BasicConstraints] | None,
        key_usage: _Extension[x509.KeyUsage] | None,
        san: _Extension[x509.SubjectAlternativeName] | Literal[True] | None,
        aki: _Extension[x509.AuthorityKeyIdentifier] | Literal[True] | None,
        ski: _Extension[x509.SubjectKeyIdentifier] | Literal[True] | None,
        name_constraints: _Extension[x509.NameConstraints] | None,
        extra_extension: _Extension[x509.ExtensionType] | None,
        parent: CertificatePair | None,
    ) -> CertificatePair:
        if subject is None:
            subject = issuer

        if serial is None:
            serial = x509.random_serial_number()

        if key is None:
            key = ec.generate_private_key(ec.SECP256R1())

        builder = x509.CertificateBuilder(
            issuer_name=issuer,
            subject_name=subject,
            public_key=key.public_key(),
            serial_number=serial,
            not_valid_before=not_before,
            not_valid_after=not_after,
        )

        if basic_constraints:
            builder = builder.add_extension(
                basic_constraints.ext,
                critical=basic_constraints.critical,
            )

        if key_usage:
            builder = builder.add_extension(key_usage.ext, critical=key_usage.critical)

        if isinstance(san, _Extension):
            builder = builder.add_extension(san.ext, san.critical)
        elif san:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False
            )

        if isinstance(aki, _Extension):
            builder = builder.add_extension(aki.ext, critical=aki.critical)
        elif aki and parent:
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    parent.cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
                ),
                critical=False,
            )
        elif aki:
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
                critical=False,
            )

        if isinstance(ski, _Extension):
            builder = builder.add_extension(ski.ext, critical=ski.critical)
        elif ski:
            builder = builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )

        if name_constraints:
            builder = builder.add_extension(
                name_constraints.ext, critical=name_constraints.critical
            )

        if extra_extension:
            builder = builder.add_extension(extra_extension.ext, critical=extra_extension.critical)

        if parent:
            cert = builder.sign(parent.key, algorithm=hashes.SHA256())
        else:
            cert = builder.sign(key, algorithm=hashes.SHA256())

        return CertificatePair(cert, key)

    def root_ca(
        self,
        *,
        issuer: x509.Name = x509.Name.from_rfc4514_string("CN=x509-limbo-root"),
        subject: x509.Name | None = None,
        serial: int | None = None,
        not_before: datetime = EPOCH,
        not_after: datetime = ONE_THOUSAND_YEARS_OF_TORMENT,
        key: CertificateIssuerPrivateKeyTypes | None = None,
        basic_constraints: _Extension[x509.BasicConstraints] | None = ext(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ),
        key_usage: _Extension[x509.KeyUsage] | None = ext(
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
        san: _Extension[x509.SubjectAlternativeName] | Literal[True] | None = True,
        aki: _Extension[x509.AuthorityKeyIdentifier] | Literal[True] | None = None,
        ski: _Extension[x509.SubjectKeyIdentifier] | Literal[True] | None = True,
        name_constraints: _Extension[x509.NameConstraints] | None = None,
        extra_extension: _Extension | None = None,
    ) -> CertificatePair:
        return self._ca(
            issuer,
            subject,
            serial,
            not_before,
            not_after,
            key,
            basic_constraints,
            key_usage,
            san,
            aki,
            ski,
            name_constraints,
            extra_extension,
            None,
        )

    def intermediate_ca(
        self,
        parent: CertificatePair,
        *,
        pathlen: int | None = None,
        issuer: x509.Name | None = None,
        subject: x509.Name | None = None,
        serial: int | None = None,
        not_before: datetime = EPOCH,
        not_after: datetime = ONE_THOUSAND_YEARS_OF_TORMENT,
        key: CertificateIssuerPrivateKeyTypes | None = None,
        basic_constraints: _Extension[x509.BasicConstraints] | Literal[True] | None = True,
        key_usage: _Extension[x509.KeyUsage] | None = ext(
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
        san: _Extension[x509.SubjectAlternativeName] | Literal[True] | None = True,
        aki: _Extension[x509.AuthorityKeyIdentifier] | Literal[True] | None = True,
        ski: _Extension[x509.SubjectKeyIdentifier] | Literal[True] | None = True,
        name_constraints: _Extension[x509.NameConstraints] | None = None,
        extra_extension: _Extension[x509.ExtensionType] | None = None,
    ) -> CertificatePair:
        """
        An intermediate CA chained up to a root CA.

        The intermediate CA has a `pathlen:N` constraint, where `N` varies.

        These intermediates can be used to assert various behaviors, including:

        * That `pathlen:N` constraints are properly honored;
        * That certificates are correctly uniqued by both their key **and** their
          subject (as each intermediate generated here shares the same key)
        """
        if pathlen is not None and isinstance(basic_constraints, _Extension):
            raise ValueError("supply only one of pathlen and basic_constraints")

        if not issuer:
            issuer = parent.cert.subject

        if not subject:
            # NOTE: Stuff the parent cert's SN into the subject here to break accidental
            # self-issuing chains.
            subject = x509.Name.from_rfc4514_string(
                f"CN=x509-limbo-intermediate-pathlen-{pathlen},OU={parent.cert.serial_number}"
            )

        if basic_constraints is True:
            basic_constraints = ext(x509.BasicConstraints(True, path_length=pathlen), critical=True)

        return self._ca(
            issuer,
            subject,
            serial,
            not_before,
            not_after,
            key,
            basic_constraints,
            key_usage,
            san,
            aki,
            ski,
            name_constraints,
            extra_extension,
            parent,
        )

    def leaf_cert(
        self,
        parent: CertificatePair,
        *,
        issuer: x509.Name | None = None,
        subject: x509.Name | Literal[True] | None = True,
        serial: int | None = None,
        not_before: datetime = EPOCH,
        not_after: datetime = ONE_THOUSAND_YEARS_OF_TORMENT,
        key: CertificateIssuerPrivateKeyTypes | None = None,
        basic_constraints: _Extension[x509.BasicConstraints] | Literal[True] | None = None,
        key_usage: _Extension[x509.KeyUsage] | None = ext(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=False,
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
        eku: _Extension[x509.ExtendedKeyUsage] | None = ext(
            x509.ExtendedKeyUsage([x509.OID_SERVER_AUTH]), critical=False
        ),
        san: _Extension[x509.SubjectAlternativeName] | Literal[True] | None = True,
        aki: _Extension[x509.AuthorityKeyIdentifier] | Literal[True] | None = True,
        extra_extension: _Extension | None = None,
        extra_unchecked_extensions: list[_Extension] | None = None,
        unchecked_version: x509.Version | None = None,
        no_extensions: bool = False,
    ) -> CertificatePair:
        """
        Produces an end-entity (EE) certificate, signed by the given `parent`'s
        key.
        """
        if subject is None:
            subject = x509.Name([])
        elif subject is True:
            subject = x509.Name.from_rfc4514_string("CN=example.com")

        if issuer is None:
            issuer = parent.cert.subject

        if serial is None:
            serial = x509.random_serial_number()

        if key is None:
            key = ec.generate_private_key(ec.SECP256R1())

        builder = x509.CertificateBuilder(serial_number=serial)
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer)
        builder = builder.not_valid_before(not_before)
        builder = builder.not_valid_after(not_after)
        builder = builder.public_key(key.public_key())
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )

        if isinstance(basic_constraints, _Extension):
            builder = builder.add_extension(
                basic_constraints.ext, critical=basic_constraints.critical
            )
        elif basic_constraints:
            builder = builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=False,
            )

        if isinstance(aki, _Extension):
            builder = builder.add_extension(aki.ext, critical=aki.critical)
        elif aki:
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(parent.key.public_key()),
                critical=False,
            )

        if key_usage:
            builder = builder.add_extension(key_usage.ext, critical=key_usage.critical)

        if eku:
            builder = builder.add_extension(eku.ext, critical=eku.critical)

        if isinstance(san, _Extension):
            builder = builder.add_extension(san.ext, san.critical)
        elif san:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False
            )

        if extra_extension is not None:
            builder = builder.add_extension(extra_extension.ext, extra_extension.critical)

        if extra_unchecked_extensions is not None:
            # NOTE: Add extension manually to bypass validation.
            for e in extra_unchecked_extensions:
                builder._extensions.append(x509.Extension(e.ext.oid, e.critical, e.ext))

        if unchecked_version is not None:
            builder._version = unchecked_version

            if unchecked_version == x509.Version.v1 and no_extensions:
                # Undo everything above if we're explicitly requesting a v1 cert.
                builder._extensions = []

        certificate = builder.sign(
            private_key=parent.key,
            algorithm=hashes.SHA256(),
        )

        return CertificatePair(certificate, key)

    def crl(
        self,
        signer: CertificatePair | None,
        *,
        issuer: x509.Name | None = None,
        last_update: datetime = EPOCH,
        next_update: datetime = ONE_THOUSAND_YEARS_OF_TORMENT,
        revoked: list[x509.RevokedCertificate] = [],
        aki: _Extension[x509.AuthorityKeyIdentifier] | Literal[True] | None = True,
        crl_number: _Extension[x509.CRLNumber] | Literal[True] | None = True,
    ) -> x509.CertificateRevocationList:
        if issuer is None:
            if signer:
                issuer = signer.cert.subject
            else:
                issuer = x509.Name.from_rfc4514_string("CN=x509-limbo-crl")

        key = signer.key if signer else ec.generate_private_key(ec.SECP256R1())

        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(issuer)
        builder = builder.last_update(last_update)
        builder = builder.next_update(next_update)

        for cert in revoked:
            builder = builder.add_revoked_certificate(cert)

        if isinstance(aki, _Extension):
            builder = builder.add_extension(aki.ext, critical=aki.critical)
        elif aki:
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
                critical=False,
            )

        if isinstance(crl_number, _Extension):
            builder = builder.add_extension(crl_number.ext, critical=crl_number.critical)
        elif crl_number:
            builder = builder.add_extension(x509.CRLNumber(1337), critical=False)

        crl = builder.sign(
            private_key=key,
            algorithm=hashes.SHA256(),
        )

        return crl

    def raw_leaf_cert(
        self,
        parent: CertificatePair,
        modifier: Callable[[str], str],
        **kwargs: Any,
    ) -> RawCertificatePair | None:
        """
        Create a leaf certificate with raw DER modification.

        This method first creates a valid leaf certificate using `leaf_cert()`,
        then applies the modifier function to the DER-ASCII representation,
        and re-signs the modified TBSCertificate.

        Requires the der-ascii tools (`der2ascii` and `ascii2der`) to be
        installed. If not available, returns None and logs a warning.

        Args:
            parent: The issuing CA certificate pair.
            modifier: Function that takes ASCII representation and returns
                modified ASCII. The modifier operates on the full certificate
                structure, but only the TBSCertificate portion will be
                extracted and re-signed.
            **kwargs: Additional arguments passed to `leaf_cert()`.

        Returns:
            RawCertificatePair containing the modified certificate and key,
            or None if der-ascii tools are not available.
        """
        # First create a valid certificate
        cert_pair = self.leaf_cert(parent, **kwargs)

        # Modify and re-sign
        modified_der = modify_certificate(
            cert_pair.cert,
            parent.key,
            modifier,
        )

        if modified_der is None:
            return None

        return RawCertificatePair(modified_der, cert_pair.key)

    def raw_crl(
        self,
        signer: CertificatePair | None,
        modifier: Callable[[str], str],
        **kwargs: Any,
    ) -> RawCRL | None:
        """
        Create a CRL with raw DER modification.

        This method first creates a valid CRL using `crl()`, then applies the
        modifier function to the DER-ASCII representation, and re-signs the
        modified TBSCertList.

        Requires the der-ascii tools (`der2ascii` and `ascii2der`) to be
        installed. If not available, returns None and logs a warning.

        Args:
            signer: The CA certificate pair that signs the CRL, or None
                for a self-signed CRL.
            modifier: Function that takes ASCII representation and returns
                modified ASCII.
            **kwargs: Additional arguments passed to `crl()`.

        Returns:
            RawCRL containing the modified CRL, or None if der-ascii tools
            are not available.
        """
        # First create a valid CRL
        crl_obj = self.crl(signer, **kwargs)

        # Get signing key
        if signer is not None:
            signing_key = signer.key
        else:
            # For self-signed CRLs, we need a key but don't have one accessible
            # This is a limitation - raw_crl requires a signer
            logger.warning("raw_crl requires a signer for re-signing")
            return None

        # Modify and re-sign
        modified_der = modify_crl(crl_obj, signing_key, modifier)

        if modified_der is None:
            return None

        return RawCRL(modified_der)

    def __init__(self, id: str, description: str):
        self._id = id
        self._conflicts_with: list[str] = []
        self._features: list[Feature] = []
        self._importance: Importance = Importance.UNDETERMINED
        self._description = description
        self._validation_kind: str | None = None
        self._trusted_certs: list[str] = []
        self._untrusted_intermediates: list[str] = []
        self._peer_certificate: str | None = None
        self._peer_certificate_key: str | None = None
        self._validation_time: datetime | None = None
        self._signature_algorithms: list[SignatureAlgorithm] = []
        self._key_usage: list[KeyUsage] = []
        self._extended_key_usage: list[KnownEKUs] = []

        self._expected_result: str | None = None
        self._expected_peer_name: PeerName | None = PeerName(kind="DNS", value="example.com")
        self._expected_peer_names: list[PeerName] = []
        self._max_chain_depth: int | None = None
        self._crls: list[str] = []

    def conflicts_with(self, *conflicting_ids: str) -> Self:
        self._conflicts_with = list(conflicting_ids)
        return self

    def features(self, feats: list[Feature]) -> Self:
        self._features = feats
        return self

    def importance(self, importance: Importance) -> Self:
        self._importance = importance
        return self

    def client_validation(self) -> Self:
        self._validation_kind = "CLIENT"
        return self

    def server_validation(self) -> Self:
        self._validation_kind = "SERVER"
        return self

    def trusted_certs(self, *certs: Certificate | RawCertificate) -> Self:
        self._trusted_certs = [c.cert_pem for c in certs]
        return self

    def untrusted_intermediates(self, *certs: Certificate | RawCertificate) -> Self:
        self._untrusted_intermediates = [c.cert_pem for c in certs]
        return self

    def peer_certificate(
        self, cert: Certificate | CertificatePair | RawCertificate | RawCertificatePair
    ) -> Self:
        self._peer_certificate = cert.cert_pem

        if isinstance(cert, (CertificatePair, RawCertificatePair)):
            self._peer_certificate_key = cert.key_pem
        return self

    def validation_time(self, time: datetime) -> Self:
        self._validation_time = time
        return self

    def signature_algorithms(self, algos: list[SignatureAlgorithm]) -> Self:
        self._signature_algorithms = algos
        return self

    def key_usage(self, usage: list[KeyUsage]) -> Self:
        self._key_usage = usage
        return self

    def extended_key_usage(self, usage: list[KnownEKUs]) -> Self:
        self._extended_key_usage = usage
        return self

    def succeeds(self) -> Self:
        self._expected_result = "SUCCESS"
        return self

    def fails(self) -> Self:
        self._expected_result = "FAILURE"
        return self

    def expected_peer_name(self, name: PeerName | None) -> Self:
        self._expected_peer_name = name
        return self

    def expected_peer_names(self, *names: PeerName) -> Self:
        self._expected_peer_names = list(names)
        return self

    def max_chain_depth(self, max_chain_depth: int) -> Self:
        self._max_chain_depth = max_chain_depth
        return self

    def crls(self, *crls: x509.CertificateRevocationList | RawCRL) -> Self:
        self._crls = [c.public_bytes(serialization.Encoding.PEM).decode() for c in crls]
        return self

    def build(self) -> Testcase:
        return Testcase(
            id=self._id,
            conflicts_with=self._conflicts_with,
            features=self._features,
            importance=self._importance,
            description=self._description,
            validation_kind=self._validation_kind,
            trusted_certs=self._trusted_certs,
            untrusted_intermediates=self._untrusted_intermediates,
            peer_certificate=self._peer_certificate,
            peer_certificate_key=self._peer_certificate_key,
            validation_time=self._validation_time,
            signature_algorithms=self._signature_algorithms,
            key_usage=self._key_usage,
            extended_key_usage=self._extended_key_usage,
            expected_result=self._expected_result,
            expected_peer_name=self._expected_peer_name,
            expected_peer_names=self._expected_peer_names,
            max_chain_depth=self._max_chain_depth,
            crls=self._crls,
        )


registry: dict[str, Callable] = {}


def testcase(func: Callable) -> Callable:
    namespace = (
        func.__module__.removeprefix("limbo.testcases.").replace(".", "::").replace("_", "-")
    )
    name = func.__name__.replace("_", "-")
    id = f"{namespace}::{name}"
    logger.debug(f"defining testcase for {id}")

    if id in registry:
        raise ValueError(f"duplicate testcase name: {id} is already registered")

    description = dedent(func.__doc__).strip() if func.__doc__ else name

    def wrapped() -> Testcase:
        logger.info(f"generating {id}")
        builder = Builder(id=id, description=description)

        func(builder)

        return builder.build()

    registry[id] = wrapped
    return wrapped
