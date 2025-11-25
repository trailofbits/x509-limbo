"""
DER manipulation utilities using der-ascii.

This module provides low-level certificate and CRL manipulation for generating
structurally invalid test cases that cannot be created with pyca/cryptography's
high-level APIs.

The workflow for modifying certificates:
1. Generate valid certificate using cryptography
2. Convert DER to ASCII with `der2ascii`
3. Modify ASCII representation (e.g., change extension values, OIDs)
4. Convert back to DER with `ascii2der`
5. Extract TBSCertificate bytes from modified DER
6. Sign TBS bytes with cryptography
7. Assemble final certificate: TBS + AlgorithmIdentifier + Signature

Requirements:
    Install der-ascii tools with:
    `go install github.com/google/der-ascii/cmd/...@latest`

    Ensure `der2ascii` and `ascii2der` are on your PATH.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from collections.abc import Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes

logger = logging.getLogger(__name__)

# ASN.1 tag for SEQUENCE
_ASN1_SEQUENCE_TAG = 0x30

# Pre-encoded AlgorithmIdentifier DER for common signature algorithms
_ALGORITHM_IDENTIFIERS: dict[tuple[type, type], bytes] = {
    # RSA with SHA-256: OID 1.2.840.113549.1.1.11
    (rsa.RSAPrivateKey, hashes.SHA256): bytes.fromhex("300d06092a864886f70d01010b0500"),
    # RSA with SHA-384: OID 1.2.840.113549.1.1.12
    (rsa.RSAPrivateKey, hashes.SHA384): bytes.fromhex("300d06092a864886f70d01010c0500"),
    # RSA with SHA-512: OID 1.2.840.113549.1.1.13
    (rsa.RSAPrivateKey, hashes.SHA512): bytes.fromhex("300d06092a864886f70d01010d0500"),
    # ECDSA with SHA-256: OID 1.2.840.10045.4.3.2
    (ec.EllipticCurvePrivateKey, hashes.SHA256): bytes.fromhex("300a06082a8648ce3d040302"),
    # ECDSA with SHA-384: OID 1.2.840.10045.4.3.3
    (ec.EllipticCurvePrivateKey, hashes.SHA384): bytes.fromhex("300a06082a8648ce3d040303"),
    # ECDSA with SHA-512: OID 1.2.840.10045.4.3.4
    (ec.EllipticCurvePrivateKey, hashes.SHA512): bytes.fromhex("300a06082a8648ce3d040304"),
}


def der_ascii_available() -> bool:
    """
    Check if der2ascii and ascii2der tools are available on PATH.

    Returns:
        True if both tools are available, False otherwise.
    """
    return shutil.which("der2ascii") is not None and shutil.which("ascii2der") is not None


def der_to_ascii(der_bytes: bytes) -> str:
    """
    Convert DER bytes to human-readable ASCII format using der2ascii.

    Args:
        der_bytes: The DER-encoded data.

    Returns:
        ASCII representation of the DER structure.

    Raises:
        subprocess.CalledProcessError: If der2ascii fails.
    """
    result = subprocess.run(
        ["der2ascii"],
        input=der_bytes,
        capture_output=True,
        check=True,
    )
    return result.stdout.decode("utf-8")


def ascii_to_der(ascii_str: str) -> bytes:
    """
    Convert ASCII format back to DER bytes using ascii2der.

    Args:
        ascii_str: The ASCII representation of DER structure.

    Returns:
        DER-encoded bytes.

    Raises:
        subprocess.CalledProcessError: If ascii2der fails.
    """
    result = subprocess.run(
        ["ascii2der"],
        input=ascii_str.encode("utf-8"),
        capture_output=True,
        check=True,
    )
    return result.stdout


def _parse_asn1_length(data: bytes, offset: int) -> tuple[int, int]:
    """
    Parse an ASN.1 length field.

    Args:
        data: The DER-encoded data.
        offset: The offset to start parsing from (should point to length byte).

    Returns:
        Tuple of (length_value, bytes_consumed).

    Raises:
        ValueError: If the length encoding is invalid.
    """
    if offset >= len(data):
        raise ValueError("Unexpected end of data while parsing length")

    first_byte = data[offset]

    # Short form: length is directly encoded in the first byte
    if first_byte < 0x80:
        return (first_byte, 1)

    # Long form: first byte indicates number of length bytes
    if first_byte == 0x80:
        raise ValueError("Indefinite length encoding not supported")

    num_length_bytes = first_byte & 0x7F
    if num_length_bytes > 4:
        raise ValueError(f"Length field too long: {num_length_bytes} bytes")

    if offset + 1 + num_length_bytes > len(data):
        raise ValueError("Unexpected end of data while parsing length")

    length = 0
    for i in range(num_length_bytes):
        length = (length << 8) | data[offset + 1 + i]

    return (length, 1 + num_length_bytes)


def _encode_asn1_length(length: int) -> bytes:
    """
    Encode a length value as ASN.1 DER length field.

    Args:
        length: The length value to encode.

    Returns:
        DER-encoded length bytes.
    """
    if length < 0x80:
        return bytes([length])

    # Determine number of bytes needed
    length_bytes: list[int] = []
    temp = length
    while temp > 0:
        length_bytes.insert(0, temp & 0xFF)
        temp >>= 8

    return bytes([0x80 | len(length_bytes)]) + bytes(length_bytes)


def _extract_first_sequence_child(der: bytes) -> bytes:
    """
    Extract the first child element from a SEQUENCE.

    This is used to extract TBSCertificate from a Certificate or
    TBSCertList from a CertificateList.

    Args:
        der: DER-encoded SEQUENCE.

    Returns:
        DER-encoded first child element.

    Raises:
        ValueError: If the DER is not a valid SEQUENCE.
    """
    if len(der) < 2:
        raise ValueError("DER data too short")

    if der[0] != _ASN1_SEQUENCE_TAG:
        raise ValueError(f"Expected SEQUENCE tag (0x30), got 0x{der[0]:02x}")

    # Parse outer SEQUENCE length
    outer_length, length_bytes = _parse_asn1_length(der, 1)
    content_start = 1 + length_bytes

    if content_start + outer_length > len(der):
        raise ValueError("SEQUENCE length exceeds data")

    # Parse first child element
    if content_start >= len(der):
        raise ValueError("SEQUENCE is empty")

    # Skip tag byte, parse length
    child_length, child_length_bytes = _parse_asn1_length(der, content_start + 1)

    child_total_length = 1 + child_length_bytes + child_length
    return der[content_start : content_start + child_total_length]


def extract_tbs_certificate(cert_der: bytes) -> bytes:
    """
    Extract the TBSCertificate from a certificate DER.

    X.509 Certificate structure:
        SEQUENCE {
            TBSCertificate SEQUENCE { ... }
            SignatureAlgorithm AlgorithmIdentifier
            SignatureValue BIT STRING
        }

    Args:
        cert_der: DER-encoded certificate.

    Returns:
        DER-encoded TBSCertificate.

    Raises:
        ValueError: If the certificate DER is invalid.
    """
    return _extract_first_sequence_child(cert_der)


def extract_tbs_cert_list(crl_der: bytes) -> bytes:
    """
    Extract the TBSCertList from a CRL DER.

    X.509 CRL structure:
        SEQUENCE {
            TBSCertList SEQUENCE { ... }
            SignatureAlgorithm AlgorithmIdentifier
            SignatureValue BIT STRING
        }

    Args:
        crl_der: DER-encoded CRL.

    Returns:
        DER-encoded TBSCertList.

    Raises:
        ValueError: If the CRL DER is invalid.
    """
    return _extract_first_sequence_child(crl_der)


def get_signature_algorithm_der(
    private_key: CertificateIssuerPrivateKeyTypes,
    algorithm: hashes.HashAlgorithm,
) -> bytes:
    """
    Get the AlgorithmIdentifier DER for a signing algorithm.

    Args:
        private_key: The private key used for signing.
        algorithm: The hash algorithm.

    Returns:
        DER-encoded AlgorithmIdentifier.

    Raises:
        ValueError: If the algorithm combination is not supported.
    """
    key_type: type
    if isinstance(private_key, rsa.RSAPrivateKey):
        key_type = rsa.RSAPrivateKey
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        key_type = ec.EllipticCurvePrivateKey
    else:
        raise TypeError(f"Unsupported key type: {type(private_key)}")

    alg_key = (key_type, type(algorithm))
    if alg_key not in _ALGORITHM_IDENTIFIERS:
        alg_name = type(algorithm).__name__
        raise ValueError(f"Unsupported algorithm: {key_type.__name__} with {alg_name}")

    return _ALGORITHM_IDENTIFIERS[alg_key]


def sign_tbs(
    tbs_bytes: bytes,
    private_key: CertificateIssuerPrivateKeyTypes,
    algorithm: hashes.HashAlgorithm = hashes.SHA256(),
) -> bytes:
    """
    Sign TBS (To-Be-Signed) bytes with a private key.

    Args:
        tbs_bytes: The TBSCertificate or TBSCertList bytes.
        private_key: The private key to sign with.
        algorithm: The hash algorithm (default: SHA256).

    Returns:
        The signature bytes.

    Raises:
        TypeError: If the key type is not supported.
    """
    if isinstance(private_key, rsa.RSAPrivateKey):
        return private_key.sign(tbs_bytes, padding.PKCS1v15(), algorithm)
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        return private_key.sign(tbs_bytes, ec.ECDSA(algorithm))
    else:
        raise TypeError(f"Unsupported key type: {type(private_key)}")


def assemble_signed_data(
    tbs_der: bytes,
    algorithm_der: bytes,
    signature: bytes,
) -> bytes:
    """
    Assemble TBS, AlgorithmIdentifier, and signature into signed data.

    This creates the outer SEQUENCE for a Certificate or CRL:
        SEQUENCE {
            TBS...
            AlgorithmIdentifier
            BIT STRING { signature }
        }

    Args:
        tbs_der: DER-encoded TBSCertificate or TBSCertList.
        algorithm_der: DER-encoded AlgorithmIdentifier.
        signature: The raw signature bytes.

    Returns:
        DER-encoded signed data (Certificate or CRL).
    """
    # Wrap signature in BIT STRING (tag 0x03)
    # First byte of content is "unused bits" (0 for signatures)
    sig_content = bytes([0]) + signature
    sig_length = _encode_asn1_length(len(sig_content))
    sig_der = bytes([0x03]) + sig_length + sig_content

    # Combine all components
    content = tbs_der + algorithm_der + sig_der

    # Wrap in outer SEQUENCE
    content_length = _encode_asn1_length(len(content))
    return bytes([_ASN1_SEQUENCE_TAG]) + content_length + content


def modify_certificate(
    cert: x509.Certificate,
    signing_key: CertificateIssuerPrivateKeyTypes,
    modifier: Callable[[str], str],
    algorithm: hashes.HashAlgorithm = hashes.SHA256(),
) -> bytes | None:
    """
    Modify a certificate's TBSCertificate and re-sign it.

    This function:
    1. Converts the certificate to ASCII representation
    2. Applies the modifier function to the ASCII
    3. Converts back to DER
    4. Extracts the modified TBSCertificate
    5. Signs it with the provided key
    6. Assembles the final certificate

    Args:
        cert: The certificate to modify.
        signing_key: The key to sign with (usually the issuer's key).
        modifier: Function that takes ASCII representation and returns modified ASCII.
        algorithm: Hash algorithm for signing (default: SHA256).

    Returns:
        DER-encoded modified certificate, or None if der-ascii is not available.
    """
    if not der_ascii_available():
        logger.warning("der-ascii tools not available, skipping certificate modification")
        return None

    # Get certificate DER and convert to ASCII
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    cert_ascii = der_to_ascii(cert_der)

    # Apply modifier
    modified_ascii = modifier(cert_ascii)

    # Convert back to DER
    modified_der = ascii_to_der(modified_ascii)

    # Extract modified TBS
    modified_tbs = extract_tbs_certificate(modified_der)

    # Sign the modified TBS
    signature = sign_tbs(modified_tbs, signing_key, algorithm)

    # Get algorithm identifier
    algorithm_der = get_signature_algorithm_der(signing_key, algorithm)

    # Assemble final certificate
    return assemble_signed_data(modified_tbs, algorithm_der, signature)


def modify_crl(
    crl: x509.CertificateRevocationList,
    signing_key: CertificateIssuerPrivateKeyTypes,
    modifier: Callable[[str], str],
    algorithm: hashes.HashAlgorithm = hashes.SHA256(),
) -> bytes | None:
    """
    Modify a CRL's TBSCertList and re-sign it.

    This function follows the same workflow as modify_certificate.

    Args:
        crl: The CRL to modify.
        signing_key: The key to sign with (usually the issuer's key).
        modifier: Function that takes ASCII representation and returns modified ASCII.
        algorithm: Hash algorithm for signing (default: SHA256).

    Returns:
        DER-encoded modified CRL, or None if der-ascii is not available.
    """
    if not der_ascii_available():
        logger.warning("der-ascii tools not available, skipping CRL modification")
        return None

    # Get CRL DER and convert to ASCII
    crl_der = crl.public_bytes(serialization.Encoding.DER)
    crl_ascii = der_to_ascii(crl_der)

    # Apply modifier
    modified_ascii = modifier(crl_ascii)

    # Convert back to DER
    modified_der = ascii_to_der(modified_ascii)

    # Extract modified TBSCertList
    modified_tbs = extract_tbs_cert_list(modified_der)

    # Sign the modified TBS
    signature = sign_tbs(modified_tbs, signing_key, algorithm)

    # Get algorithm identifier
    algorithm_der = get_signature_algorithm_der(signing_key, algorithm)

    # Assemble final CRL
    return assemble_signed_data(modified_tbs, algorithm_der, signature)
