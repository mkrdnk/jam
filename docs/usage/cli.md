---
title: CLI
---

# Jam CLI

Jam CLI is just a tool for generating different keys. For example, it is suitable for debugging with real keys or convenient deployment.

## Installation

```bash
pip install jamlib[cli]
```

## Usage

```bash
$ jam [OPTIONS] COMMAND [ARGS]...
```

### Options
* `--version`: Show the version and exit.
* `--help`: Show help message and exit.

## Commands
* `keychain`: Administer configured KeyChains.
* `keys`: Generate cryptographic keys.
* `password`: Password hashing and verification utilities.

### Keychain
See [keychain documentation](/usage/keychain/#cli).

### Keys
Generate cryptographic keys.

```bash
$ jam keys COMMAND [ARGS]...
```

#### Commands
* `aes`: Generate AES key.
* `ecdsa`: Generate ECDSA P-384 key pair.
* `ed25519`: Generate Ed25519 key pair.
* `rsa`: Generate RSA key pair.
* `symmetric`: Generate symmetric key.

### Password
Password hashing and verification utilities.

```bash
$ jam password [OPTIONS] COMMAND [ARGS]...
```

#### Commands
* `hash`: Hash a password.
* `verify`: Verify a password against a hash.
