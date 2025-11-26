"""
Models and definitions for generating certificate assets for Limbo testcases.
"""

from __future__ import annotations

import base64
import datetime
import logging
from dataclasses import dataclass
from functools import cached_property
from importlib import resources
from typing import Generic, TypeVar

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.x509 import ExtensionType

# NOTE: We judiciously start on the second *after* the Unix epoch, since
# some path validation libraries intentionally reject anything on or
# before the epoch.
EPOCH = datetime.datetime.utcfromtimestamp(1)
ONE_THOUSAND_YEARS_OF_TORMENT = EPOCH + datetime.timedelta(days=365 * 1000)
ASSETS_PATH = resources.files("limbo._assets")
_ExtensionType = TypeVar("_ExtensionType", bound=ExtensionType)


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Certificate:
    """
    An X.509 certificate.
    """

    cert: x509.Certificate

    @cached_property
    def cert_pem(self) -> str:
        return self.cert.public_bytes(encoding=serialization.Encoding.PEM).decode()


@dataclass(frozen=True)
class CertificatePair(Certificate):
    """
    An X.509 certificate and its associated private key.
    """

    key: CertificateIssuerPrivateKeyTypes

    @cached_property
    def key_pem(self) -> str:
        return self.key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()


@dataclass(frozen=True)
class _Extension(Generic[_ExtensionType]):
    """
    An X.509 extension and its criticality.
    """

    ext: _ExtensionType
    critical: bool


def ext(extension: _ExtensionType, *, critical: bool) -> _Extension[_ExtensionType]:
    """
    Constructs a new _Extension to pass into certificate builder helpers.
    """
    return _Extension(extension, critical)


def _der_to_pem(der_bytes: bytes, label: str) -> str:
    """
    Convert DER bytes to PEM format with the given label.

    Args:
        der_bytes: The DER-encoded data.
        label: The PEM label (e.g., "CERTIFICATE", "X509 CRL").

    Returns:
        PEM-encoded string.
    """
    b64 = base64.b64encode(der_bytes).decode("ascii")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"


@dataclass(frozen=True)
class RawCertificate:
    """
    A certificate represented as raw DER bytes.

    This class provides the same `cert_pem` interface as `Certificate`,
    but wraps raw DER bytes instead of a parsed x509.Certificate object.
    Useful for certificates that have been modified at the DER level and
    cannot be parsed by the cryptography library.
    """

    cert_der: bytes

    @cached_property
    def cert_pem(self) -> str:
        """Return PEM-encoded certificate."""
        return _der_to_pem(self.cert_der, "CERTIFICATE")


@dataclass(frozen=True)
class RawCertificatePair(RawCertificate):
    """
    A raw certificate with its associated private key.

    This class provides the same interface as `CertificatePair`,
    but wraps raw DER bytes instead of a parsed x509.Certificate object.
    """

    key: CertificateIssuerPrivateKeyTypes

    @cached_property
    def key_pem(self) -> str:
        """Return PEM-encoded private key."""
        return self.key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()


@dataclass(frozen=True)
class RawCRL:
    """
    A CRL represented as raw DER bytes.

    This class provides compatibility with x509.CertificateRevocationList
    for methods that accept CRLs. Useful for CRLs that have been modified
    at the DER level.
    """

    crl_der: bytes

    def public_bytes(self, encoding: serialization.Encoding) -> bytes:
        """
        Return the CRL bytes in the requested encoding.

        Args:
            encoding: The encoding format (DER or PEM).

        Returns:
            The encoded CRL bytes.
        """
        if encoding == serialization.Encoding.DER:
            return self.crl_der
        elif encoding == serialization.Encoding.PEM:
            return _der_to_pem(self.crl_der, "X509 CRL").encode()
        else:
            raise ValueError(f"Unsupported encoding: {encoding}")
