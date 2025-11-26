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

### Downloading the Test Suite

Due to the large size of `limbo.json` (39MB+), we recommend downloading it from
the [latest release](https://github.com/C2SP/x509-limbo/releases/latest) rather
than cloning the entire repository. Each release includes:

- `limbo.json` - The complete test suite
- `limbo-schema.json` - The JSON schema for the test suite
- Python package wheels for easy installation

## Developing

This repository contains a self-managing tool called `limbo`.

```bash
make dev && source env/bin/activate

limbo --help
```

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

## Releasing

To create a new release:

1. Update the version in `limbo/__init__.py`
2. Commit the version bump: `git commit -am "Bump version to X.Y.Z"`
3. Create and push a tag: `git tag vX.Y.Z && git push origin vX.Y.Z`
4. The GitHub Actions workflow will automatically:
   - Build the Python package
   - Generate `limbo.json`
   - Create a GitHub release with all assets
   - Publish to PyPI (if `PYPI_TOKEN` secret is configured)

The release will include `limbo.json` and `limbo-schema.json` as downloadable
assets, avoiding the need to keep the large `limbo.json` file in the repository.

## Licensing

This repository and the Limbo testsuite are licensed under the Apache License,
version 2.0.

This repository additionally contains testcases that are generated from
the [BetterTLS](https://github.com/Netflix/bettertls) project, which
is also licensed under the Apache License, version 2.0.
