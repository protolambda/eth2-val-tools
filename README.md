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
      --host-meta-loc string        Path of the metadat of the output wallet for the host, where keymanageropts.json, secrets dir, acc_path_to_pub.json are written (default "assigned_wallet_meta")
      --host-wallet-loc string      Path of the output wallet for the host, where a keystore of assigned keys is written (default "assigned_wallet")
      --host-wallet-name string     Name of the wallet, applicable if e.g. an ethdo wallet type. (default "Assigned")
      --host-wallet-pass string     Pass for the output wallet itself. Empty to disable
      --hostname string             Unique name of the remote host to assign validators to (default "morty")
      --out-wallet-type string      Type of the output wallet. Either 'hd' (hierarchical deterministic) or 'nd' (non-deterministic) (default "nd")
      --source-keys-csv string      CSV of source key passwords. Account name (with wallet prefix), account password
      --source-wallet-loc string    Path of the source wallet, empty to use default
      --source-wallet-name string   Name of the wallet to look for keys in (default "Validators")
      --source-wallet-pass string   Pass for the source wallet itself. Empty to disable
```

Account names will be the hex-encoded pubkey of the respective account.

## License

MIT, see [`LICENSE`](./LICENSE) file.

