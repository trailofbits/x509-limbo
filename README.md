# x509-limbo

⚠️ This is a work in progress! ⚠️

A suite of testvectors (and associated tooling) for X.509 certificate path
validation.

This project is maintained as part of the [C2SP](https://c2sp.org) project.
It was originally created by [Trail of Bits](https://www.trailofbits.com).

## How to use this repository

This repository contains canned testcases for developing or testing
implementations of X.509 path validation.

To use it, you'll need to understand (and use) two pieces:

1. [`limbo-schema.json`](./limbo-schema.json): The testcase schema. This is
   provided as a [JSON Schema](https://json-schema.org/) definition.
2. [`limbo.json`](./limbo.json): The combined testcase
   suite. The structure of this file conforms to the schema above.

The schema will tell you how to consume the combined testcase suite.

## Developing

This repository contains a self-managing tool called `limbo`.

```bash
make dev && source env/bin/activate

limbo --help
```

### Optional: DER manipulation support

Some test cases require low-level DER manipulation to create structurally
invalid certificates. This functionality requires Google's
[der-ascii](https://github.com/google/der-ascii) tools to be installed.

```bash
# Requires Go 1.20+
go install github.com/google/der-ascii/cmd/...@latest
```

Ensure the Go bin directory is on your PATH (typically `~/go/bin`).

If der-ascii is not available, test cases using `raw_leaf_cert()` or
`raw_crl()` will be skipped gracefully (methods return `None` and log a
warning).

This tool can be used to regenerate the schema, as well as
develop and manage testcases and testcase assets:

```bash
limbo schema --help
limbo compile --help
```

There are also two convenience `make` targets for quickly regenerating
the schema and test suite:

```bash
make limbo-schema.json
make limbo.json
```

## Licensing

This repository and the Limbo testsuite are licensed under the Apache License,
version 2.0.

This repository additionally contains testcases that are generated from
the [BetterTLS](https://github.com/Netflix/bettertls) project, which
is also licensed under the Apache License, version 2.0.
