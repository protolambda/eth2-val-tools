# Validator management tools

*Warning: Use at your own risk, this is all very experimental*

## Commands

### `assign`

This keeps track of validator assignments in a json file, protected from concurrent use with a lock file.

You can then make assignments of `n` validators, generating a wallet to use on the host the validators were assigned to.

The source wallet format assumes [Ethdo](https://github.com/wealdtech/ethdo),
 using the [Eth2-client-wallet library](https://github.com/wealdtech/go-eth2-wallet).

```
Assign `n` available validators to `hostname`. If --add is true, it will add `n` assigned validators, instead of filling up to `n` total assigned to the host

Usage:
  eth2-val-tools assign [flags]

Flags:
      --add                         If the assignment should add to the existing assignment
      --assignments string          Path of the current assignments to adjust (default "assignments.json")
  -n, --count uint                  Amount of validators to assign
  -h, --help                        help for assign
      --hostname string             Unique name of the remote host to assign validators to (default "morty")
      --key-man-loc string          Location to write to the 'location' field in the keymanager_opts.json file (Prysm only)
      --out-loc string              Path of the output data for the host, where wallets, keys, secrets dir, etc. are written (default "assigned_data")
      --source-keys-csv string      CSV of source key passwords. Account name (with wallet prefix), account password
      --source-wallet-loc string    Path of the source wallet, empty to use default
      --source-wallet-name string   Name of the wallet to look for keys in (default "Validators")
      --source-wallet-pass string   Pass for the source wallet itself. Empty to disable

```

### Output

Eth2 clients structure their validators differently, but this tool outputs all the required data for each of them.

#### Prysm

Prysm is a special case, they are centric around the Ethdo wallet system. Instead of using the EIP 2335 key files directly, like all the other clients.

In the output directory, a `prysm` dir is placed, with the following contents:

- `keymanager_opts.json`: JSON file describing accounts and their passphrases. And the "Location" part can be configured with `--key-man-loc`,
 which will point to some "wallets" directory: where the actual wallets can be found.
  - Prysm requires Account names listed in the JSON to be prefixied with the wallet name, separated by a `/`. Like `Assigned/foobarvalidator`.
  - Ethdo wallets are in the same big store, and only one directory in this store per wallet. The directory must be named as UUID, and in the directory there must be a file with the same UUID name to describe the wallet.
  - Ethdo key files in the wallet must also be named as a UUID, so that they can be parsed in the `.Accounts()` call
- `wallets`: a directory which is an Ethdo store with a single non-deterministic wallet in it, covering all keys.
  - The wallet name is called `Assigned`, and the keys are `Assigned/val_<pubkey here>` (excluding `<` and `>`) The pubkey is hex encoded, without `0x`.
  - The wallet also contains an `index` file and all other ethdo-specific things

#### Lighthouse

Lighthouse is key-centric, no wallets involved. Following EIP 2335.

The output is:

- `secrets` directory, containing one file per validator. Named after the pubkey (hex-encoded, `0x` prefix).
 Each file contains the passphrase for the `voting-keystore.json` of the validator.
- `keys` directory (equivalent of `.lighthouse/validators`, containing one directory per validator. Named after the pubkey (hex-encoded, `0x` prefix).
 Each directory contains a `voting-keystore.json`, an EIP 2335 keystore file, with `path` field set to empty string.
 The `voting-keystore.json` name is a requirement of Lighthouse.

#### Teku

Like Lighthouse, Teku is also key-centric, but requires you to be explicit about finding keys. I.e. you need the CLI options:
```
--encrypted-keystore-validator-file=foobar/key.json
--encrypted-keystore-validator-password-file=secrets/foobar
```

This matches lighthouse close enough, but is clumsy. To make this easier, a `pubkeys.json` file is provided, 
 with a list of hex encoded pubkeys (to replace `foobar` with in above example).

## License

MIT, see [`LICENSE`](./LICENSE) file.

