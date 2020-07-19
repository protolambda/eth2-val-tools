#!/bin/bash

# Generate a random one with `eth2-val-tools mnemonic`
# These are BIP39 mnemonics
export VALIDATORS_MNEMONIC="enough animal salon barrel poet method husband evidence grain excuse grass science there wedding blind glimpse surge loan reopen chalk toward change survey bag"
export WITHDRAWALS_MNEMONIC="stay depend ignore lady access will dress idea hybrid tube original riot between plate ethics ecology green response hollow famous salute they warrior little"

# TODO: insert fork version here
# E.g. "0x00000113" for witti testnet
export FORK_VERSION="0x00000123"

# Range of accounts to create, deposit, etc.
# Incl.
export ACC_START_INDEX=0
# Excl.
export ACC_END_INDEX=15

# TODO: Insert deposit contract address here
export DEPOSIT_CONTRACT_ADDRESS="0xcccccccccccccccccccccccccccccccccccccccc"
export DEPOSIT_DATAS_FILE="./deposit_datas.txt"

# What the deposit tx will send, change to 0Ether for testnet deposit contracts if necessary
export DEPOSIT_ACTUAL_VALUE="32Ether"
# What the deposit data will include (in Gwei)
export DEPOSIT_AMOUNT="32000000000"

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
