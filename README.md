# Validator management tools

__*Warning: Use at your own RISK, this is all very EXPERIMENTAL*__

## Deposits

Optionally install [`ethereal`](https://github.com/wealdtech/ethereal/), to run the `exec_deposits.sh` step. 

Important: when installing, run the commands outside of the root directory of this repository, to not mix up the go modules.

```shell script
# Install this assignments tool
go install .

# Move out of this dir
cd ..

# Install ethereal
GO111MODULE=on go get github.com/wealdtech/ethereal 
```

Steps:
- `eth2-val-tools mnemonic`, twice: one for validator keys, one for withdrawal keys. Put them in the config.
- `. my_config.sh`: central configuration with environment vars, see `example_config.sh` for an example
- `. build_deposits.sh`: uses the mnemonics to generate deposit data for the configured range of accounts. (overwrites any existing deposit data file)
- `. exec_deposits.sh`: executes deposit datas, making eth1 transactions

For automatic validator assignment, tracking and deployment, use the `assign` command of the Go module in this repo. 

## Commands

### `keystores`

Builds keystores/secrets in every format, for a given mnemonic and account range.

```
Usage:
  eth2-val-tools keystores [flags]

Flags:
  -h, --help                     help for keystores
      --insecure                 Enable to output insecure keystores (faster generation, ONLY for ephemeral private testnets
      --out-loc string           Path of the output data for the host, where wallets, keys, secrets dir, etc. are written (default "assigned_data")
      --prysm-pass string        Password for all-accounts keystore file (Prysm only)
      --source-max uint          Maximum validator index in HD path range (excl.)
      --source-min uint          Minimum validator index in HD path range (incl.)
      --source-mnemonic string   The validators mnemonic to source account keys from.

```

### `mnemonic`

Outputs a bare 256 bit entropy BIP39 mnemonic, or stops with exit code 1.

```
Create a random mnemonic

Usage:
  eth2-val-tools mnemonic [flags]

Flags:
  -h, --help   help for mnemonic
```

### `deposit-data`

To quickly generate a list of deposit datas for a range of accounts.

```
Create deposit data for the given range of validators. 1 json-encoded deposit data per line.

Usage:
  eth2-val-tools deposit-data [flags]

Flags:
      --amount uint                   Amount to deposit, in Gwei (default 32000000000)
      --fork-version string           Fork version, e.g. 0x11223344
  -h, --help                          help for deposit-data
      --source-max uint               Maximum validator index in HD path range (excl.)
      --source-min uint               Minimum validator index in HD path range (incl.)
      --validators-mnemonic string    Mnemonic to use for validators.
      --withdrawals-mnemonic string   Mnemonic to use for withdrawals. Withdrawal accounts are assumed to have matching paths with validators.
```

### `pubkeys`

List pubkeys of the given range of validators. Output encoded as one pubkey per line.

Example, list pubkeys (for a random new mnemonic), account range `[42, 123)`:
```shell script
eth2-val-tools pubkeys --validators-mnemonic="$(eth2-val-tools mnemonic)" --source-min=42 --source-max=123
```

## Output

Eth2 clients structure their validators differently, but this tool outputs all the required data for each of them.

### Prysm

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

### Lighthouse

Lighthouse is key-centric, no wallets involved. Following EIP 2335.

The output is:

- `secrets` directory, containing one file per validator. Named after the pubkey (hex-encoded, `0x` prefix).
 Each file contains the passphrase for the `voting-keystore.json` of the validator.
- `keys` directory (equivalent of `.lighthouse/validators`, containing one directory per validator. Named after the pubkey (hex-encoded, `0x` prefix).
 Each directory contains a `voting-keystore.json`, an EIP 2335 keystore file, with `path` field set to empty string.
 The `voting-keystore.json` name is a requirement of Lighthouse.

### Nimbus

Nimbus, a lot like lighthouse, expects a keys and secrets directory, which can be configured.
Each keystore is named `keystore.json` instead of `voting-keystore.json` however.
For ease of use, an additional `nimbus-keys` directory will be output, with this naming scheme.

### Teku

Like Lighthouse, Teku is also key-centric, but requires you to be explicit about finding keys. I.e. you need the CLI options:
```
--encrypted-keystore-validator-file=foobar/key.json
--encrypted-keystore-validator-password-file=secrets/foobar
```

This matches lighthouse close enough, but is clumsy. To make this easier,
 a teku configuration file is output, with the validator mappings configured for you.

### Lodestar

Lodestar is very similar to Lighthouse/Nimbus, but has 3 directories:
```
  --keystoresDir="{{keystores_relative_dir}}"
  --secretsDir="{{secrets_relative_dir}}"
  --validatorsDbDir="{{validators_db_relative_dir}}"
```

These directories are relative to the `--rootDir` directory.
The keystores dir has pubkey-named directories, each with a `voting-keystore.json`.
The secrets dir has pubkey-named files containing passwords, but the pubkey in the names are encoded without the `0x` prefix.
The validators-DB dir is unimportant, and can be left empty. This is managed by lodestar.

## License

MIT, see [`LICENSE`](./LICENSE) file.

