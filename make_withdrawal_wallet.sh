#!/bin/bash

echo "USE AT YOUR OWN RISK"
read -p "Are you sure? " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
fi

# E.g. "./wallets/witti"
walletbasedir=$WALLET_DIR

#wallet_type="hierarchical deterministic"
wallet_type="non-deterministic"

withdrawal_wallet_name="Withdrawal"
withdrawal_account_name="Primary"

withdrawal_wallet_passphrase=$WITHRAWAL_WALLET_PASSWORD
withdrawal_account_passphrase=$WITHRAWAL_ACC_PASSWORD

mkdir -p "$walletbasedir"

echo "Creating withdrawal wallet: $withdrawal_wallet_name in $walletbasedir"

$GOPATH/bin/ethdo wallet create \
   --type="$wallet_type" \
   --basedir="$walletbasedir" \
   --wallet="$withdrawal_wallet_name" \
   --walletpassphrase="$withdrawal_wallet_passphrase"

echo "Creating withdrawal account: $withdrawal_wallet_name/$withdrawal_account_name"

# Create single withdrawal account
$GOPATH/bin/ethdo account create \
   --basedir="$walletbasedir" \
   --account="$withdrawal_wallet_name/$withdrawal_account_name" \
   --walletpassphrase="$withdrawal_wallet_passphrase" \
   --passphrase="$withdrawal_account_passphrase"
