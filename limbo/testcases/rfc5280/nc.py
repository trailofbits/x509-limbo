"""
RFC 5280 Name Constraints (NC) testcases.
"""

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from limbo.assets import ext
from limbo.models import Feature, KnownEKUs, PeerName
from limbo.testcases._core import Builder, testcase


@testcase
def permitted_dns_mismatch(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with a permitted dNSName
    "example.com", whereas the leaf certificate has a SubjectAlternativeName with a
    dNSName of "not-example.com".
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.DNSName("example.com")], excluded_subtrees=None
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root,
        san=ext(x509.SubjectAlternativeName([x509.DNSName("not-example.com")]), critical=False),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).fails()


@testcase
def excluded_dns_match(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> ICA -> leaf
    ```

    The ICA contains a NameConstraints extension with an excluded dNSName of
    "example.com", matching the leaf's SubjectAlternativeName.
    """
    root = builder.root_ca()
    ica = builder.intermediate_ca(
        root,
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=None, excluded_subtrees=[x509.DNSName("example.com")]
            ),
            critical=True,
        ),
    )
    leaf = builder.leaf_cert(
        ica, san=ext(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False)
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).untrusted_intermediates(ica).peer_certificate(
        leaf
    ).expected_peer_name(PeerName(kind="DNS", value="example.com")).fails()


@testcase
def permitted_dns_match(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with a permitted dNSName of
    "example.com", matching the leaf's SubjectAlternativeName.
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.DNSName("example.com")], excluded_subtrees=None
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root, san=ext(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False)
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).succeeds()


@testcase
def permitted_dns_match_noncritical(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with a permitted dNSName of
    "example.com", matching the leaf's SubjectAlternativeName. However,
    the NameConstraints extension is not marked as critical, which is required by
    the RFC 5280 profile.
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.DNSName("example.com")], excluded_subtrees=None
            ),
            critical=False,
        )
    )
    leaf = builder.leaf_cert(
        root, san=ext(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False)
    )

    builder = (
        builder.server_validation()
        .conflicts_with("webpki::nc::permitted-dns-match-noncritical")
        .features([Feature.rfc5280_incompatible_with_webpki])
        .trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="example.com"))
        .fails()
    )


@testcase
def permitted_dns_match_more(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with a permitted dNSName of
    "example.com". The leaf's "foo.bar.example.com" satisfies this constraint
    per the RFC 5280 profile:

    > DNS name restrictions are expressed as host.example.com.  Any DNS
    > name that can be constructed by simply adding zero or more labels to
    > the left-hand side of the name satisfies the name constraint.  For
    > example, www.host.example.com would satisfy the constraint but
    > host1.example.com would not.
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.DNSName("example.com")], excluded_subtrees=None
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root,
        san=ext(x509.SubjectAlternativeName([x509.DNSName("foo.bar.example.com")]), critical=False),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="foo.bar.example.com")
    ).succeeds()


@testcase
def excluded_dns_match_second(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with an excluded dNSName of
    "not-allowed.example.com". This should match the leaf's second
    SubjectAlternativeName entry.
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=None, excluded_subtrees=[x509.DNSName("not-allowed.example.com")]
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName(
                [x509.DNSName("example.com"), x509.DNSName("not-allowed.example.com")]
            ),
            critical=False,
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def permitted_ip_mismatch(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with a permitted iPAddress of
    `192.0.2.0/24`, which does not match the iPAddress in the SubjectAlternativeName
    of the leaf.
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.IPAddress(IPv4Network("192.0.2.0/24"))],
                excluded_subtrees=None,
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName([x509.IPAddress(IPv4Address("192.0.3.1"))]), critical=False
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="IP", value="192.0.3.1")
    ).fails()


@testcase
def excluded_ipv4_match(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with an excluded iPAddress of
    `192.0.2.0/24`, matching the iPAddress in the SubjectAlternativeName of the leaf.
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=None,
                excluded_subtrees=[x509.IPAddress(IPv4Network("192.0.2.0/24"))],
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName([x509.IPAddress(IPv4Address("192.0.2.1"))]), critical=False
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="IP", value="192.0.2.1")
    ).fails()


@testcase
def excluded_ipv6_match(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with an excluded iPAddress of
    `::1/128`, matching the iPAddress in the SubjectAlternativeName of the leaf.
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=None,
                excluded_subtrees=[x509.IPAddress(IPv6Network("::1/128"))],
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root,
        san=ext(x509.SubjectAlternativeName([x509.IPAddress(IPv6Address("::1"))]), critical=False),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="IP", value="::1")
    ).fails()


@testcase
def permitted_ipv4_match(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with a permitted iPAddress of
    `192.0.2.0/24`, which matches the iPAddress in the SubjectAlternativeName
    of the leaf.
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.IPAddress(IPv4Network("192.0.2.0/24"))],
                excluded_subtrees=None,
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName([x509.IPAddress(IPv4Address("192.0.2.1"))]), critical=False
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="IP", value="192.0.2.1")
    ).succeeds()


@testcase
def permitted_ipv6_match(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with a permitted iPAddress of
    `::1/128`, which matches the iPAddress in the SubjectAlternativeName
    of the leaf.
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.IPAddress(IPv6Network("::1/128"))],
                excluded_subtrees=None,
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root,
        san=ext(x509.SubjectAlternativeName([x509.IPAddress(IPv6Address("::1"))]), critical=False),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="IP", value="::1")
    ).succeeds()


@testcase
def permitted_dn_mismatch(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with a permitted DirectoryName
    of `CN=foo`. This should not match the child's DirectoryName of `CN=not-foo`.
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.DirectoryName(x509.Name.from_rfc4514_string("CN=foo"))],
                excluded_subtrees=None,
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root,
        subject=x509.Name.from_rfc4514_string("CN=not-foo"),
        san=ext(
            x509.SubjectAlternativeName(
                [x509.DirectoryName(x509.Name.from_rfc4514_string("CN=not-foo"))]
            ),
            critical=False,
        ),
    )

    builder = builder.server_validation().features([Feature.name_constraint_dn])
    builder.trusted_certs(root).peer_certificate(leaf).fails()


@testcase
def excluded_dn_match(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with an excluded DirectoryName
    of `CN=foo`, matching the leaf's SubjectAlternativeName.
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=None,
                excluded_subtrees=[x509.DirectoryName(x509.Name.from_rfc4514_string("CN=foo"))],
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root,
        subject=x509.Name.from_rfc4514_string("CN=foo"),
        san=ext(
            x509.SubjectAlternativeName(
                [x509.DirectoryName(x509.Name.from_rfc4514_string("CN=foo"))]
            ),
            critical=False,
        ),
    )

    builder = builder.server_validation().features([Feature.name_constraint_dn])
    builder.trusted_certs(root).peer_certificate(leaf).fails()


@testcase
def permitted_dn_match(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with a permitted DirectoryName
    of `CN=foo`, matching the leaf's SubjectAlternativeName.
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.DirectoryName(x509.Name.from_rfc4514_string("CN=foo"))],
                excluded_subtrees=None,
            ),
            critical=True,
        ),
        san=None,
    )
    leaf = builder.leaf_cert(
        root,
        subject=x509.Name.from_rfc4514_string("CN=foo"),
        san=ext(
            x509.SubjectAlternativeName(
                [x509.DirectoryName(x509.Name.from_rfc4514_string("CN=foo"))]
            ),
            critical=False,
        ),
    )

    builder = builder.server_validation().features([Feature.name_constraint_dn])
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(None).succeeds()


@testcase
def permitted_dn_match_subject_san_mismatch(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with a permitted DirectoryName
    of "CN=foo", matching the leaf's SubjectAlternativeName but not its subject.
    The leaf must be rejected per RFC 5280 4.2.1.10 due to this mismatch:

    > Restrictions of the form directoryName MUST be applied to the subject
    > field in the certificate (when the certificate includes a non-empty
    > subject field) and to any names of type directoryName in the
    > subjectAltName extension.
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.DirectoryName(x509.Name.from_rfc4514_string("CN=foo"))],
                excluded_subtrees=None,
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root,
        subject=x509.Name.from_rfc4514_string("CN=not-foo"),
        san=ext(
            x509.SubjectAlternativeName(
                [x509.DirectoryName(x509.Name.from_rfc4514_string("CN=foo"))]
            ),
            critical=False,
        ),
    )

    builder = builder.server_validation().features([Feature.name_constraint_dn])
    builder.trusted_certs(root).peer_certificate(leaf).fails()


@testcase
def excluded_dn_match_sub_mismatch(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with an excluded DirectoryName
    of "CN=foo", matching the leaf's subject but not its SubjectAlternativeName.
    The leaf must be rejected per RFC 5280 4.2.1.10 due to this match:

    > Restrictions of the form directoryName MUST be applied to the subject
    > field in the certificate (when the certificate includes a non-empty
    > subject field) and to any names of type directoryName in the
    > subjectAltName extension.
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=None,
                excluded_subtrees=[x509.DirectoryName(x509.Name.from_rfc4514_string("CN=foo"))],
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root,
        subject=x509.Name.from_rfc4514_string("CN=foo"),
        san=ext(
            x509.SubjectAlternativeName(
                [x509.DirectoryName(x509.Name.from_rfc4514_string("CN=not-foo"))]
            ),
            critical=False,
        ),
    )

    builder = builder.server_validation().features([Feature.name_constraint_dn])
    builder.trusted_certs(root).peer_certificate(leaf).fails()


# NOTE: The following tests aren't specific to any name constraint type.
# We could potentially parametrize this for different constraint types.
@testcase
def permitted_self_issued(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> intermediate -> leaf
    ```

    The root contains a NameConstraints extension with a permitted dNSName of
    "example.com", whereas the intermediate certificate has a
    SubjectAlternativeName with a dNSName of "not-example.com".

    Normally, this would mean that the chain would be rejected, however the
    intermediate is self-issued so name constraints don't apply to it.

    > Name constraints are not applied to self-issued certificates (unless
    > the certificate is the final certificate in the path).  (This could
    > prevent CAs that use name constraints from employing self-issued
    > certificates to implement key rollover.)
    """
    root = builder.root_ca(
        issuer=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "not-example.com")]),
        subject=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "not-example.com")]),
        san=ext(x509.SubjectAlternativeName([x509.DNSName("not-example.com")]), critical=False),
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.DNSName("example.com")],
                excluded_subtrees=None,
            ),
            critical=True,
        ),
    )
    intermediate = builder.intermediate_ca(
        root,
        issuer=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "not-example.com")]),
        subject=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "not-example.com")]),
        san=ext(x509.SubjectAlternativeName([x509.DNSName("not-example.com")]), critical=False),
    )
    leaf = builder.leaf_cert(intermediate)
    builder = builder.server_validation()
    builder.trusted_certs(root).untrusted_intermediates(intermediate).peer_certificate(
        leaf
    ).succeeds()


@testcase
def excluded_self_issued_leaf(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> intermediate -> leaf
    ```

    The root contains a NameConstraints extension with a permitted dNSName of
    "example.com", whereas the leaf certificate has a SubjectAlternativeName
    with a dNSName of "not-example.com".

    In this case, the chain would still be rejected as name constraints do apply
    to self-issued certificates if they are in the leaf position.

    > Name constraints are not applied to self-issued certificates (unless
    > the certificate is the final certificate in the path).  (This could
    > prevent CAs that use name constraints from employing self-issued
    > certificates to implement key rollover.)
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.DNSName("example.com")],
                excluded_subtrees=None,
            ),
            critical=True,
        )
    )
    intermediate = builder.intermediate_ca(
        root,
        subject=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "not-example.com")]),
        san=ext(x509.SubjectAlternativeName([x509.DNSName("not-example.com")]), critical=False),
    )
    leaf = builder.leaf_cert(
        intermediate,
        issuer=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "not-example.com")]),
        subject=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "not-example.com")]),
        san=ext(x509.SubjectAlternativeName([x509.DNSName("not-example.com")]), critical=False),
    )
    builder = builder.server_validation()
    builder.trusted_certs(root).untrusted_intermediates(intermediate).peer_certificate(
        leaf
    ).expected_peer_name(PeerName(kind="DNS", value="not-example.com")).fails()


@testcase
def excluded_match_permitted_and_excluded(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with a permitted and excluded
    dNSName of "example.com", both of which match the leaf's
    SubjectAlternativeName.

    The excluded constraint takes precedence over the the permitted so this
    chain should be marked as invalid.
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.DNSName("example.com")],
                excluded_subtrees=[x509.DNSName("example.com")],
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root,
        san=ext(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False),
    )
    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def permitted_different_constraint_type(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with a permitted iPAddress of
    `192.0.2.0/24`, while the leaf's SubjectAlternativeName is a dNSName.
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.IPAddress(IPv4Network("192.0.2.0/24"))],
                excluded_subtrees=None,
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root,
        san=ext(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False),
    )
    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).succeeds()


@testcase
def excluded_different_constraint_type(builder: Builder) -> None:
    """
    Produces the following **valid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with an excluded iPAddress of
    `192.0.2.0/24`, while the leaf's SubjectAlternativeName is a dNSName.
    """
    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=None,
                excluded_subtrees=[x509.IPAddress(IPv4Network("192.0.2.0/24"))],
            ),
            critical=True,
        )
    )
    leaf = builder.leaf_cert(
        root,
        san=ext(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False),
    )
    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).succeeds()


@testcase
def invalid_dnsname_wildcard(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> leaf
    ```

    The root contains a Name Constraints extension with a malformed dNSName
    (uses a wildcard pattern, which is not permitted under RFC 5280).
    """

    # NOTE: Set `_permitted_subtrees` directly to avoid validation.
    name_constraints = x509.NameConstraints(
        permitted_subtrees=[x509.DNSName("unrelated.cryptography.io")], excluded_subtrees=None
    )
    name_constraints._permitted_subtrees = [x509.DNSName("*.example.com")]

    root = builder.root_ca(name_constraints=ext(name_constraints, critical=True))
    leaf = builder.leaf_cert(
        root,
        san=ext(x509.SubjectAlternativeName([x509.DNSName("foo.example.com")]), critical=False),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="foo.example.com")
    ).fails()


@testcase
def invalid_dnsname_leading_period(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> leaf
    ```

    The root contains a Name Constraint extension with a malformed DNS name
    (uses a leading period, which is not permitted under RFC 5280 4.2.1.10).

    This is widely (incorrectly) accepted by implementations due to OpenSSL
    accepting it and due to misreadings of RFC 5280, which allows a leading
    period in *URI* constraints but not DNS constraints.
    """

    # NOTE: Set `_permitted_subtrees` directly to avoid validation.
    name_constraints = x509.NameConstraints(
        permitted_subtrees=[x509.DNSName("unrelated.cryptography.io")], excluded_subtrees=None
    )
    name_constraints._permitted_subtrees = [x509.DNSName(".example.com")]

    root = builder.root_ca(name_constraints=ext(name_constraints, critical=True))
    leaf = builder.leaf_cert(
        root,
        san=ext(x509.SubjectAlternativeName([x509.DNSName("foo.example.com")]), critical=False),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="foo.example.com")
    ).fails()


@testcase
def invalid_ipv4_address(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with a malformed IPv4
    iPAddress (not in CIDR form).
    """

    # NOTE: Set `_permitted_subtrees` directly to avoid validation.
    name_constraints = x509.NameConstraints(
        permitted_subtrees=[x509.IPAddress(IPv4Network("0.0.0.0/8"))], excluded_subtrees=None
    )
    name_constraints._permitted_subtrees = [x509.IPAddress(IPv4Address("127.0.0.1"))]

    root = builder.root_ca(name_constraints=ext(name_constraints, critical=True))
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName([x509.IPAddress(IPv4Address("127.0.0.1"))]), critical=False
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="IP", value="127.0.0.1")
    ).fails()


@testcase
def invalid_ipv6_address(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> leaf
    ```

    The root contains a NameConstraints extension with a malformed IPv6
    iPAddress (not in CIDR form).
    """

    # NOTE: Set `_permitted_subtrees` directly to avoid validation.
    name_constraints = x509.NameConstraints(
        permitted_subtrees=[x509.IPAddress(IPv6Network("::1/128"))], excluded_subtrees=None
    )
    name_constraints._permitted_subtrees = [x509.IPAddress(IPv6Address("::1"))]

    root = builder.root_ca(name_constraints=ext(name_constraints, critical=True))
    leaf = builder.leaf_cert(
        root,
        san=ext(x509.SubjectAlternativeName([x509.IPAddress(IPv6Address("::1"))]), critical=False),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="IP", value="::1")
    ).fails()


@testcase
def invalid_email_address(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> leaf
    ```

    The root contains a `NameConstraints` extension with a malformed
    RFC822 name constraint (`invalid@invalid@example.com`, which is not
    a valid email address).
    """
    # NOTE: Set `_permitted_subtrees` directly to avoid validation.
    name_constraints = x509.NameConstraints(
        permitted_subtrees=[x509.RFC822Name("fake@example.com")], excluded_subtrees=None
    )
    name_constraints._permitted_subtrees = [
        x509.RFC822Name._init_without_validation("invalid@invalid@example.com")
    ]

    root = builder.root_ca(name_constraints=ext(name_constraints, critical=True))
    leaf = builder.leaf_cert(
        root,
        san=ext(
            x509.SubjectAlternativeName([x509.RFC822Name("example@example.com")]), critical=False
        ),
        eku=ext(
            x509.ExtendedKeyUsage([x509.OID_CLIENT_AUTH]),
            critical=False,
        ),
    )

    builder = (
        builder.client_validation()
        .extended_key_usage([KnownEKUs.client_auth])
        .trusted_certs(root)
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="example@example.com"))
        .fails()
    )


@testcase
def not_allowed_in_ee_noncritical(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The EE contains a non-critical NameConstraints extension, which is not
    permitted under the RFC 5280 profile:

    > The name constraints extension, which MUST be used only in a CA certificate
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        extra_extension=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.DNSName("example.com")],
                excluded_subtrees=None,
            ),
            critical=False,
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def not_allowed_in_ee_critical(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> EE
    ```

    The EE contains a critical NameConstraints extension, which is not
    permitted under the RFC 5280 profile:

    > The name constraints extension, which MUST be used only in a CA certificate
    """

    root = builder.root_ca()
    leaf = builder.leaf_cert(
        root,
        extra_extension=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.DNSName("example.com")],
                excluded_subtrees=None,
            ),
            critical=True,
        ),
    )

    builder = builder.server_validation()
    builder.trusted_certs(root).peer_certificate(leaf).expected_peer_name(
        PeerName(kind="DNS", value="example.com")
    ).fails()


@testcase
def intermediate_with_san_rejected_by_intermediate_nc(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> ICA1 -> ICA2 -> EE
             |       |       |
             |       |       |
             NC     SAN1    SAN2
    ```

    ICA1 contains a NameConstraints extension that forbids
    SAN1 (forbidden.example.com) and permits SAN2 (permitted.example.com),
    which should be rejected under RFC 5280:

    > The name constraints extension, which MUST be used only in a CA
    > certificate, indicates a name space within which all subject names in
    > subsequent certificates in a certification path MUST be located.
    """

    root = builder.root_ca()
    ica1 = builder.intermediate_ca(
        root,
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.DNSName("permitted.example.com")],
                excluded_subtrees=[x509.DNSName("forbidden.example.com")],
            ),
            critical=True,
        ),
    )
    ica2 = builder.intermediate_ca(
        ica1,
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("forbidden.example.com")]), critical=False
        ),
    )
    leaf = builder.leaf_cert(
        ica2,
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("permitted.example.com")]), critical=False
        ),
    )

    builder = (
        builder.server_validation()
        .trusted_certs(root)
        .untrusted_intermediates(ica1, ica2)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="permitted.example.com"))
        .fails()
    )


@testcase
def intermediate_with_san_rejected_by_root_nc(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> ICA1 -> ICA2 -> EE
     |               |       |
     |               |       |
     NC             SAN1    SAN2
    ```

    The root contains a NameConstraints extension that forbids
    SAN1 (forbidden.example.com) and permits SAN2 (permitted.example.com),
    which should be rejected under RFC 5280:

    > The name constraints extension, which MUST be used only in a CA
    > certificate, indicates a name space within which all subject names in
    > subsequent certificates in a certification path MUST be located.
    """

    root = builder.root_ca(
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.DNSName("permitted.example.com")],
                excluded_subtrees=[x509.DNSName("forbidden.example.com")],
            ),
            critical=True,
        ),
    )
    ica1 = builder.intermediate_ca(root)
    ica2 = builder.intermediate_ca(
        ica1,
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("forbidden.example.com")]), critical=False
        ),
    )
    leaf = builder.leaf_cert(
        ica2,
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("permitted.example.com")]), critical=False
        ),
    )

    builder = (
        builder.server_validation()
        .trusted_certs(root)
        .untrusted_intermediates(ica1, ica2)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="permitted.example.com"))
        .fails()
    )


@testcase
def restrictive_permits_in_intermediates_narrows(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root     ->     ICA1     ->     ICA2     ->     EE
                     |               |               |
                  permits:        permits:       SAN: foo.example.com
              foo.example.com   bar.example.com
              bar.example.com
    ```

    ICA1 contains a NameConstraints extension permitting `foo.example.com`
    and `bar.example.com`, while ICA2 contains a NameConstraints extension
    permitting only `bar.example.com`. The EE then contains a SAN for
    `foo.example.com`, which should be rejected under RFC 5280:

    > a name space within which all subject names in
    > subsequent certificates in a certification path MUST be located.
    """

    root = builder.root_ca()
    ica1 = builder.intermediate_ca(
        root,
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[
                    x509.DNSName("foo.example.com"),
                    x509.DNSName("bar.example.com"),
                ],
                excluded_subtrees=None,
            ),
            critical=True,
        ),
    )
    ica2 = builder.intermediate_ca(
        ica1,
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.DNSName("bar.example.com")], excluded_subtrees=None
            ),
            critical=True,
        ),
    )
    leaf = builder.leaf_cert(
        ica2,
        san=ext(x509.SubjectAlternativeName([x509.DNSName("foo.example.com")]), critical=False),
    )

    builder = (
        builder.server_validation()
        .trusted_certs(root)
        .untrusted_intermediates(ica1, ica2)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="foo.example.com"))
        .fails()
    )


@testcase
def restrictive_permits_in_intermediates_widens(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root     ->     ICA1     ->     ICA2     ->     EE
                     |               |               |
                  permits:        permits:       SAN: foo.example.com
              bar.example.com   foo.example.com
                                bar.example.com
    ```

    ICA1 contains a NameConstraints extension permitting only `bar.example.com`,
    while ICA2 contains a NameConstraints extension permitting `foo.example.com`
    and `bar.example.com`. The EE then contains a SAN for `foo.example.com`,
    which should be rejected under RFC 5280:

    > a name space within which all subject names in
    > subsequent certificates in a certification path MUST be located.
    """

    root = builder.root_ca()
    ica1 = builder.intermediate_ca(
        root,
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[
                    x509.DNSName("bar.example.com"),
                ],
                excluded_subtrees=None,
            ),
            critical=True,
        ),
    )
    ica2 = builder.intermediate_ca(
        ica1,
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[
                    x509.DNSName("foo.example.com"),
                    x509.DNSName("bar.example.com"),
                ],
                excluded_subtrees=None,
            ),
            critical=True,
        ),
    )
    leaf = builder.leaf_cert(
        ica2,
        san=ext(x509.SubjectAlternativeName([x509.DNSName("foo.example.com")]), critical=False),
    )

    builder = (
        builder.server_validation()
        .trusted_certs(root)
        .untrusted_intermediates(ica1, ica2)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="foo.example.com"))
        .fails()
    )


@testcase
def nc_permits_invalid_dns_san(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> ICA (NC: example.com) -> EE (SAN: .example.com)
    ```

    The ICA contains a NC that allows `example.com` and all subdomains,
    but the EE's SAN contains a malformed DNS name (`.example.com`). This should
    fail per RFC 5280, since all names MUST be located within the
    permitted namespace.
    """

    root = builder.root_ca()
    intermediate = builder.intermediate_ca(
        root,
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.DNSName("example.com")], excluded_subtrees=None
            ),
            critical=True,
        ),
    )
    leaf = builder.leaf_cert(
        intermediate,
        san=ext(
            x509.SubjectAlternativeName(
                [x509.DNSName(".example.com"), x509.DNSName("foo.example.com")]
            ),
            critical=False,
        ),
    )

    builder = (
        builder.server_validation()
        .trusted_certs(root)
        .untrusted_intermediates(intermediate)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="foo.example.com"))
        .fails()
    )


@testcase
def nc_permits_invalid_ip_san(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> ICA (NC: 192.0.2.0/24) -> EE (SAN: 192.0.2.0/24)
    ```

    The ICA contains a NC that permits 192.0.2.0/24, but the EE's SAN
    is malformed (containing a CIDR range instead of an IP address). This should
    fail per RFC 5280, since all names MUST be located within the
    permitted namespace.
    """

    root = builder.root_ca()
    intermediate = builder.intermediate_ca(
        root,
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.IPAddress(IPv4Network("192.0.2.0/24"))],
                excluded_subtrees=None,
            ),
            critical=True,
        ),
    )
    leaf = builder.leaf_cert(
        intermediate,
        san=ext(
            x509.SubjectAlternativeName(
                [
                    x509.IPAddress(IPv4Network("192.0.2.0/24")),
                    x509.IPAddress(IPv4Address("192.0.2.1")),
                ]
            ),
            critical=False,
        ),
    )

    builder = (
        builder.server_validation()
        .trusted_certs(root)
        .untrusted_intermediates(intermediate)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="IP", value="192.0.2.1"))
        .fails()
    )


@testcase
def nc_permits_invalid_email_san(builder: Builder) -> None:
    """
    Produces the following **invalid** chain:

    ```
    root -> ICA (NC: example.com) -> EE (SAN: invalid@address@example.com)
    ```

    The ICA contains a NC that permits any email inbox on `example.com`,
    but the EE's SAN is malformed (containing a malformed email address).
    This should fail per RFC 5280, since all names MUST be located within the
    permitted namespace.
    """

    root = builder.root_ca()
    intermediate = builder.intermediate_ca(
        root,
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.RFC822Name("example.com")],
                excluded_subtrees=None,
            ),
            critical=True,
        ),
    )
    leaf = builder.leaf_cert(
        intermediate,
        san=ext(
            x509.SubjectAlternativeName(
                [
                    x509.RFC822Name("good@example.com"),
                    x509.RFC822Name("alsogood@example.com"),
                    x509.RFC822Name._init_without_validation("invalid@address@example.com"),
                ]
            ),
            critical=False,
        ),
        eku=ext(
            x509.ExtendedKeyUsage([x509.OID_CLIENT_AUTH]),
            critical=False,
        ),
    )

    builder = (
        builder.client_validation()
        .extended_key_usage([KnownEKUs.client_auth])
        .trusted_certs(root)
        .untrusted_intermediates(intermediate)
        .peer_certificate(leaf)
        .expected_peer_names(
            PeerName(kind="RFC822", value="good@example.com"),
            PeerName(kind="RFC822", value="alsogood@example.com"),
        )
        .fails()
    )


@testcase
def nc_forbids_alternate_chain_ica(builder: Builder) -> None:
    """
    Produces the following **valid** graph:

    ```
    EE (SAN:X) +-> ICA_B' (SAN:Y) -> No root to chain to
               |-> ICA_B'' (no SAN) -> ICA_A (NC forbids SAN:Y) -> Root
    ```

    `ICA_B'` and `ICA_B''` are certificates for the same logical intermediate,
    but issued by different logical root CAs.

    This graph allows validation through `EE -> ICA_B'' -> Root`.
    """

    discarded_root = builder.root_ca(san=None)
    trusted_root = builder.root_ca(san=None)

    ica_a = builder.intermediate_ca(
        trusted_root,
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.DNSName("permitted.example.com")],
                excluded_subtrees=[x509.DNSName("forbidden.example.com")],
            ),
            critical=True,
        ),
        san=None,
    )

    ica_key = ec.generate_private_key(ec.SECP256R1())
    ica_b_1 = builder.intermediate_ca(
        discarded_root,
        key=ica_key,
        subject=x509.Name.from_rfc4514_string("CN=an-intermediate"),
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("forbidden.example.com")]), critical=False
        ),
    )
    ica_b_2 = builder.intermediate_ca(
        ica_a,
        key=ica_key,
        subject=x509.Name.from_rfc4514_string("CN=an-intermediate"),
        san=None,
    )

    leaf = builder.leaf_cert(
        ica_b_1,
        subject=x509.Name.from_rfc4514_string("CN=permitted.example.com"),
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("permitted.example.com")]), critical=False
        ),
    )

    builder = (
        builder.server_validation()
        .trusted_certs(trusted_root)
        .untrusted_intermediates(ica_a, ica_b_1, ica_b_2)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="permitted.example.com"))
        .succeeds()
    )


@testcase
def nc_forbids_same_chain_ica(builder: Builder) -> None:
    """
    Produces the following **valid** graph:

    ```
    EE (SAN:X) +-> ICA_B' (SAN:Y) -> ICA_A (forbid: SAN:Y) -> RCA_A
               |-> ICA_B'' (SAN:Z) -> RCA_B (no NC)
    ```

    `ICA_B'` and `ICA_B''` are certificates for the same logical intermediate,
    but chained to different logical root CAs. Both root CAs are trusted,
    but `ICA_B'` is issued through `ICA_A`, which forbids `ICA_B'`'s SAN.

    This graph allows validation through `EE -> ICA_B'' -> RCA_B`
    """

    root_a = builder.root_ca(san=None)
    root_b = builder.root_ca(san=None)

    ica_a = builder.intermediate_ca(
        root_a,
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=None, excluded_subtrees=[x509.DNSName("forbidden.example.com")]
            ),
            critical=True,
        ),
        san=None,
    )

    ica_b_key = ec.generate_private_key(ec.SECP256R1())
    ica_b_1 = builder.intermediate_ca(
        ica_a,
        key=ica_b_key,
        subject=x509.Name.from_rfc4514_string("CN=an-intermediate"),
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("forbidden.example.com")]), critical=False
        ),
    )
    ica_b_2 = builder.intermediate_ca(
        root_b,
        key=ica_b_key,
        subject=x509.Name.from_rfc4514_string("CN=an-intermediate"),
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("unconstrained-ica.example.com")]),
            critical=False,
        ),
    )

    leaf = builder.leaf_cert(
        ica_b_1,
        subject=x509.Name.from_rfc4514_string("CN=unconstrained.example.com"),
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("unconstrained.example.com")]), critical=False
        ),
    )

    builder = (
        builder.server_validation()
        .trusted_certs(root_a, root_b)
        .untrusted_intermediates(ica_a, ica_b_1, ica_b_2)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="unconstrained.example.com"))
        .succeeds()
    )


@testcase
def nc_permits_email_exact(builder: Builder) -> None:
    """
    Produces the following **valid** graph:

    ```
    root -> ICA (permit: foo@example.com) -> EE (SAN: foo@example.com)
    ```

    Per RFC 5280 4.2.1.10 an email name constraint may specify a particular mailbox,
    like in this graph.
    """

    root = builder.root_ca()
    ica = builder.intermediate_ca(
        root,
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.RFC822Name("foo@example.com")], excluded_subtrees=None
            ),
            critical=True,
        ),
        san=None,
    )
    leaf = builder.leaf_cert(
        ica,
        san=ext(x509.SubjectAlternativeName([x509.RFC822Name("foo@example.com")]), critical=False),
        eku=ext(
            x509.ExtendedKeyUsage([x509.OID_CLIENT_AUTH]),
            critical=False,
        ),
    )

    builder = (
        builder.client_validation()
        .extended_key_usage([KnownEKUs.client_auth])
        .trusted_certs(root)
        .untrusted_intermediates(ica)
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="foo@example.com"))
        .succeeds()
    )


@testcase
def nc_permits_email_domain(builder: Builder) -> None:
    """
    Produces the following **valid** graph:

    ```
    root -> ICA (permit: example.com) -> EE (SAN: foo@example.com)
    ```

    Per RFC 5280 4.2.1.10 an email name constraint may specify a host name to
    constrain all inboxes on that host.
    """

    root = builder.root_ca()
    ica = builder.intermediate_ca(
        root,
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.RFC822Name("example.com")], excluded_subtrees=None
            ),
            critical=True,
        ),
        san=None,
    )
    leaf = builder.leaf_cert(
        ica,
        san=ext(x509.SubjectAlternativeName([x509.RFC822Name("foo@example.com")]), critical=False),
        eku=ext(
            x509.ExtendedKeyUsage([x509.OID_CLIENT_AUTH]),
            critical=False,
        ),
    )

    builder = (
        builder.client_validation()
        .extended_key_usage([KnownEKUs.client_auth])
        .trusted_certs(root)
        .untrusted_intermediates(ica)
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="foo@example.com"))
        .succeeds()
    )


@testcase
def nc_permits_email_literal_asterisk_exact_match(builder: Builder) -> None:
    """
    Produces the following **valid** graph:

    ```
    root -> ICA (permit: *@example.com) -> EE (SAN: *@example.com)
    ```

    Per RFC 5280 4.2.1.10, an asterisk in an email name constraint is a literal
    character, not a wildcard. The constraint `*@example.com` should permit the
    exact mailbox `*@example.com`.
    """
    # Bypass validation for literal asterisk in constraint
    name_constraints = x509.NameConstraints(
        permitted_subtrees=[x509.RFC822Name("fake@example.com")], excluded_subtrees=None
    )
    name_constraints._permitted_subtrees = [
        x509.RFC822Name._init_without_validation("*@example.com")
    ]

    root = builder.root_ca()
    ica = builder.intermediate_ca(
        root,
        name_constraints=ext(name_constraints, critical=True),
        san=None,
    )
    leaf = builder.leaf_cert(
        ica,
        san=ext(
            x509.SubjectAlternativeName(
                [x509.RFC822Name._init_without_validation("*@example.com")]
            ),
            critical=False,
        ),
        eku=ext(
            x509.ExtendedKeyUsage([x509.OID_CLIENT_AUTH]),
            critical=False,
        ),
    )

    builder = (
        builder.client_validation()
        .extended_key_usage([KnownEKUs.client_auth])
        .trusted_certs(root)
        .untrusted_intermediates(ica)
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="*@example.com"))
        .succeeds()
    )


@testcase
def nc_permits_email_literal_asterisk_rejects_user(builder: Builder) -> None:
    """
    Produces the following **invalid** graph:

    ```
    root -> ICA (permit: *@example.com) -> EE (SAN: user@example.com)
    ```

    Per RFC 5280 4.2.1.10, an asterisk in an email name constraint is a literal
    character, not a wildcard. The constraint `*@example.com` should NOT match
    `user@example.com` because the asterisk must match literally, not as a
    pattern.
    """
    # Bypass validation for literal asterisk in constraint
    name_constraints = x509.NameConstraints(
        permitted_subtrees=[x509.RFC822Name("fake@example.com")], excluded_subtrees=None
    )
    name_constraints._permitted_subtrees = [
        x509.RFC822Name._init_without_validation("*@example.com")
    ]

    root = builder.root_ca()
    ica = builder.intermediate_ca(
        root,
        name_constraints=ext(name_constraints, critical=True),
        san=None,
    )
    leaf = builder.leaf_cert(
        ica,
        san=ext(
            x509.SubjectAlternativeName([x509.RFC822Name("user@example.com")]),
            critical=False,
        ),
        eku=ext(
            x509.ExtendedKeyUsage([x509.OID_CLIENT_AUTH]),
            critical=False,
        ),
    )

    builder = (
        builder.client_validation()
        .extended_key_usage([KnownEKUs.client_auth])
        .trusted_certs(root)
        .untrusted_intermediates(ica)
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="user@example.com"))
        .fails()
    )


@testcase
def nc_permits_email_literal_asterisk_rejects_subdomain(builder: Builder) -> None:
    """
    Produces the following **invalid** graph:

    ```
    root -> ICA (permit: *@example.com) -> EE (SAN: *@subdomain.example.com)
    ```

    Per RFC 5280 4.2.1.10, the constraint `*@example.com` should NOT match
    `*@subdomain.example.com` because they are different domains, and the
    asterisk is a literal character in both cases.
    """
    # Bypass validation for literal asterisk in constraint
    name_constraints = x509.NameConstraints(
        permitted_subtrees=[x509.RFC822Name("fake@example.com")], excluded_subtrees=None
    )
    name_constraints._permitted_subtrees = [
        x509.RFC822Name._init_without_validation("*@example.com")
    ]

    root = builder.root_ca()
    ica = builder.intermediate_ca(
        root,
        name_constraints=ext(name_constraints, critical=True),
        san=None,
    )
    leaf = builder.leaf_cert(
        ica,
        san=ext(
            x509.SubjectAlternativeName(
                [x509.RFC822Name._init_without_validation("*@subdomain.example.com")]
            ),
            critical=False,
        ),
        eku=ext(
            x509.ExtendedKeyUsage([x509.OID_CLIENT_AUTH]),
            critical=False,
        ),
    )

    builder = (
        builder.client_validation()
        .extended_key_usage([KnownEKUs.client_auth])
        .trusted_certs(root)
        .untrusted_intermediates(ica)
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="*@subdomain.example.com"))
        .fails()
    )


@testcase
def nc_permits_email_literal_double_asterisk(builder: Builder) -> None:
    """
    Produces the following **valid** graph:

    ```
    root -> ICA (permit: **@example.com) -> EE (SAN: **@example.com)
    ```

    Per RFC 5280 4.2.1.10, any characters in an email name constraint are treated
    literally. The constraint `**@example.com` should permit only the exact
    mailbox `**@example.com`.
    """
    # Bypass validation for literal asterisks in constraint
    name_constraints = x509.NameConstraints(
        permitted_subtrees=[x509.RFC822Name("fake@example.com")], excluded_subtrees=None
    )
    name_constraints._permitted_subtrees = [
        x509.RFC822Name._init_without_validation("**@example.com")
    ]

    root = builder.root_ca()
    ica = builder.intermediate_ca(
        root,
        name_constraints=ext(name_constraints, critical=True),
        san=None,
    )
    leaf = builder.leaf_cert(
        ica,
        san=ext(
            x509.SubjectAlternativeName(
                [x509.RFC822Name._init_without_validation("**@example.com")]
            ),
            critical=False,
        ),
        eku=ext(
            x509.ExtendedKeyUsage([x509.OID_CLIENT_AUTH]),
            critical=False,
        ),
    )

    builder = (
        builder.client_validation()
        .extended_key_usage([KnownEKUs.client_auth])
        .trusted_certs(root)
        .untrusted_intermediates(ica)
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="**@example.com"))
        .succeeds()
    )


@testcase
def nc_permits_email_literal_double_asterisk_rejects_single(builder: Builder) -> None:
    """
    Produces the following **invalid** graph:

    ```
    root -> ICA (permit: **@example.com) -> EE (SAN: *@example.com)
    ```

    Per RFC 5280 4.2.1.10, the constraint `**@example.com` should NOT match
    `*@example.com` because the asterisks are literal characters, not wildcards.
    """
    # Bypass validation for literal asterisks in constraint
    name_constraints = x509.NameConstraints(
        permitted_subtrees=[x509.RFC822Name("fake@example.com")], excluded_subtrees=None
    )
    name_constraints._permitted_subtrees = [
        x509.RFC822Name._init_without_validation("**@example.com")
    ]

    root = builder.root_ca()
    ica = builder.intermediate_ca(
        root,
        name_constraints=ext(name_constraints, critical=True),
        san=None,
    )
    leaf = builder.leaf_cert(
        ica,
        san=ext(
            x509.SubjectAlternativeName(
                [x509.RFC822Name._init_without_validation("*@example.com")]
            ),
            critical=False,
        ),
        eku=ext(
            x509.ExtendedKeyUsage([x509.OID_CLIENT_AUTH]),
            critical=False,
        ),
    )

    builder = (
        builder.client_validation()
        .extended_key_usage([KnownEKUs.client_auth])
        .trusted_certs(root)
        .untrusted_intermediates(ica)
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="*@example.com"))
        .fails()
    )


@testcase
def nc_permits_email_literal_mid_asterisk(builder: Builder) -> None:
    """
    Produces the following **valid** graph:

    ```
    root -> ICA (permit: user*@example.com) -> EE (SAN: user*@example.com)
    ```

    Per RFC 5280 4.2.1.10, all characters in an email name constraint are treated
    literally, including asterisks at any position. The constraint
    `user*@example.com` should permit only the exact mailbox `user*@example.com`.
    """
    # Bypass validation for literal asterisk in constraint
    name_constraints = x509.NameConstraints(
        permitted_subtrees=[x509.RFC822Name("fake@example.com")], excluded_subtrees=None
    )
    name_constraints._permitted_subtrees = [
        x509.RFC822Name._init_without_validation("user*@example.com")
    ]

    root = builder.root_ca()
    ica = builder.intermediate_ca(
        root,
        name_constraints=ext(name_constraints, critical=True),
        san=None,
    )
    leaf = builder.leaf_cert(
        ica,
        san=ext(
            x509.SubjectAlternativeName(
                [x509.RFC822Name._init_without_validation("user*@example.com")]
            ),
            critical=False,
        ),
        eku=ext(
            x509.ExtendedKeyUsage([x509.OID_CLIENT_AUTH]),
            critical=False,
        ),
    )

    builder = (
        builder.client_validation()
        .extended_key_usage([KnownEKUs.client_auth])
        .trusted_certs(root)
        .untrusted_intermediates(ica)
        .peer_certificate(leaf)
        .expected_peer_names(PeerName(kind="RFC822", value="user*@example.com"))
        .succeeds()
    )


@testcase
def nc_forbids_othername(builder: Builder) -> None:
    """
    Produces the following **invalid** graph:

    ```
    root -> ICA (forbid: ON) -> EE (SAN: ON)
    ```

    RFC 5280 does not specify the handling other OtherName constraints,
    but does specify that implementations must either process (and
    therefore recognize) all constraints or outright reject the certificate.

    > If a name constraints extension that is marked as critical
    > imposes constraints on a particular name form, and an instance of
    > that name form appears in the subject field or subjectAltName
    > extension of a subsequent certificate, then the application MUST
    > either process the constraint or reject the certificate.

    This testcase contains an ICA with a private OtherName (meaning the
    implementation will not recognize it), and therefore must reject the chain.
    """

    private_on_oid = x509.ObjectIdentifier("1.3.6.1.4.1.55738.666.3")
    der_null = b"\x05\x00"

    root = builder.root_ca()
    ica = builder.intermediate_ca(
        root,
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.DNSName("example.com")],
                excluded_subtrees=[x509.OtherName(private_on_oid, der_null)],
            ),
            critical=True,
        ),
        san=None,
    )
    leaf = builder.leaf_cert(
        ica,
        san=ext(
            x509.SubjectAlternativeName(
                [x509.DNSName("example.com"), x509.OtherName(private_on_oid, der_null)]
            ),
            critical=False,
        ),
    )

    builder = (
        builder.server_validation()
        .trusted_certs(root)
        .untrusted_intermediates(ica)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="example.com"))
        .fails()
    )


@testcase
def nc_forbids_othername_noop(builder: Builder) -> None:
    """
    Produces the following **valid** graph:

    ```
    root -> ICA (forbid: ON) -> EE (SAN: no ON)
    ```

    RFC 5280 does not specify the handling other OtherName constraints,
    but does specify that implementations are only required to evaluate constraints
    for names that actually appear on the validation path.

    In this case, ICA contains an OtherName Name Constraint but no actual SANs
    on the path contain any OtherName subjects, making the chain valid.
    """

    private_on_oid = x509.ObjectIdentifier("1.3.6.1.4.1.55738.666.3")
    der_null = b"\x05\x00"

    root = builder.root_ca()
    ica = builder.intermediate_ca(
        root,
        name_constraints=ext(
            x509.NameConstraints(
                permitted_subtrees=[x509.DNSName("example.com")],
                excluded_subtrees=[x509.OtherName(private_on_oid, der_null)],
            ),
            critical=True,
        ),
        san=None,
    )
    leaf = builder.leaf_cert(
        ica,
        san=ext(
            x509.SubjectAlternativeName([x509.DNSName("example.com")]),
            critical=False,
        ),
    )

    builder = (
        builder.server_validation()
        .trusted_certs(root)
        .untrusted_intermediates(ica)
        .peer_certificate(leaf)
        .expected_peer_name(PeerName(kind="DNS", value="example.com"))
        .succeeds()
    )
