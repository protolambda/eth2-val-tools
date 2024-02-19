# Legacy deposits script

Collection of legacy (3+ year old) util/dev scripts.
These are not supported anymore.

## `check_deposit.py`

Debug script to analyze a deposit, using the consensus-layer python spec.

## Legacy deposit automation

Install [`ethereal`](https://github.com/wealdtech/ethereal/), to run the `exec_deposits.sh` step.

Important: when installing, run the commands outside of the root directory of this repository, to not mix up the go modules.

```shell script
cd ..

# Install eth2-val-tools
go install .

# Move out of this dir
cd ..

# Install ethereal
GO111MODULE=on go install github.com/wealdtech/ethereal@latest
```

Steps:
- `eth2-val-tools mnemonic`, twice: one for validator keys, one for withdrawal keys. Put them in the config.
- `. my_config.sh`: central configuration with environment vars, see `example_config.sh` for an example
- `. build_deposits.sh`: uses the mnemonics to generate deposit data for the configured range of accounts. (overwrites any existing deposit data file)
- `. exec_deposits.sh`: executes deposit datas, making eth1 transactions

For automatic validator assignment, tracking and deployment, use the `assign` command of the Go module in this repo. 
