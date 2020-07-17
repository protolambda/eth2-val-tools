#!/bin/bash

echo "USE AT YOUR OWN RISK"
read -p "Are you sure? " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
fi

walletbasedir=$WALLET_DIR

validator_wallet_name="Validators"
validator_wallet_passphrase=$VALIDATORS_WALLET_PASSWORD

account_start=$ACC_START_INDEX
account_end=$ACC_END_INDEX

mkdir -p "$walletbasedir"

echo "Creating validator wallet"

# Create wallet
~/go/bin/ethdo wallet create \
   --type="hierarchical deterministic" \
   --debug=true \
   --basedir="$walletbasedir" \
   --wallet="$validator_wallet_name" \
   --walletpassphrase="$validator_wallet_passphrase"

for ((i=$account_start;i<$account_end;i++));
do
   account_name="$validator_wallet_name/$i"
   echo "Creating validator account $account_name"

   ~/go/bin/ethdo account create \
      --basedir="$walletbasedir" \
      --account="$account_name" \
      --store="filesystem" \
      --walletpassphrase="$validator_wallet_passphrase"

done
