#!/bin/bash

export VALIDATORS_WALLET_NAME="Validators"
# Warning: bad open passwords, use something else
# Do not have weak plain passwords like this open for non-test environments.
# Note: Only HD wallets are supported as source. Thus only wallet passwords, no account passwords.
# *change these*
export VALIDATORS_WALLET_PASSWORD="foo"
export WITHDRAWALS_WALLET_PASSWORD="bar"

export VALIDATORS_WALLET_NAME="Validators"
export WITHDRAWALS_WALLET_NAME="Withdrawals"

# TODO: insert fork version here
# E.g. "0x00000113" for witti testnet
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

# What the deposit tx will send, change to 0Ether for testnet deposit contracts if necessary
export DEPOSIT_ACTUAL_VALUE="32Ether"
# What the deposit data will include
export DEPOSIT_AMOUNT="32Ether"

# DO NOT DO THIS IN MAINNET
# With testnets you can be lazy and directly use a Goerli Eth1 keypair
# *change these*
export ETH1_FROM_ADDR="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
export ETH1_FROM_PRIV="0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

# The deposit contract of Altona is not recognized, so we're forcing deposits through anyway
# Required for testnets that are not recognized by ethdo
export FORCE_DEPOSIT=true

# Eth1 network ID as used by Ethdo
export ETH1_NETWORK=goerli
