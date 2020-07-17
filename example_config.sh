#!/bin/bash

# Warning: bad open passwords, use something else
# Do not have weak plain passwords like this open for non-test environments.
# *change these*
export VALIDATORS_WALLET_PASSWORD="foo"
export WITHRAWAL_WALLET_PASSWORD="bar"
export WITHRAWAL_ACC_PASSWORD="quix"

# TODO: insert fork version here, e.g. '0x12abcdef`
export FORK_VERSION="TODO"
export WALLET_DIR="./wallets/altona"

# This is where the passwords go for each of the accounts that will be generated
export ACCOUNT_PASSWORDS_LOC="./wallets/altona/val_passwords.csv"

# Range of accounts to create, deposit, etc.
# Incl.
export ACC_START_INDEX=0
# Excl.
export ACC_END_INDEX=15

# TODO: Insert deposit contract address here
export DEPOSIT_CONTRACT_ADDRESS="TODO"
export DEPOSIT_DATAS_FILE="./wallets/altona/deposit_datas.txt"


# DO NOT DO THIS IN MAINNET
# With testnets you can be lazy and directly use a Goerli Eth1 keypair
# *change these*
export ETH1_FROM_ADDR="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
export ETH1_FROM_PRIV="0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

# The deposit contract of Altona is not recognized, so we're forcing deposits through anyway
export FORCE_DEPOSIT=true
