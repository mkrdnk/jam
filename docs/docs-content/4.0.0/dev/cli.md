# CLI

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
Administer configured KeyChains.

```bash
$ jam keychain [OPTIONS] COMMAND [ARGS]...
```

#### Options
* `--config FILE`: Jam configuration file containing keychains.

#### Commands
* `activate`: Make a key current and retire the old current key.
* `add`: Generate a standby key.
* `current`: Show the current issuing key.
* `list`: List key metadata.
* `remove`: Permanently delete a non-current key.
* `retire`: Retire a key while retaining it for verification.
* `revoke`: Immediately reject credentials using a compromised key.
* `rotate`: Generate and activate a new key.
* `show`: Show metadata for one key.


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
