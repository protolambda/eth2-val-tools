#!/bin/bash

echo "USE AT YOUR OWN RISK"
read -p "Are you sure? " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
fi

walletbasedir=$WALLET_DIR
account_passwords_csv_file=$ACCOUNT_PASSWORDS_LOC

validator_wallet_name="$VALIDATORS_WALLET_NAME"
validator_wallet_passphrase=$VALIDATORS_WALLET_PASSWORD

account_start=$ACC_START_INDEX
account_end=$ACC_END_INDEX

# HD wallet work in progress, need to update tooling to support wallet-passwords.
#wallet_type="hierarchical deterministic"
wallet_type="non-deterministic"

mkdir -p "$walletbasedir"

echo "Creating validator wallet"

# Create wallet
ethdo wallet create \
   --type="$wallet_type" \
   --debug=true \
   --basedir="$walletbasedir" \
   --wallet="$validator_wallet_name" \
   --walletpassphrase="$validator_wallet_passphrase"

for ((i=$account_start;i<=$account_end;i++));
do
   account_name="$validator_wallet_name/$i"
   echo "Creating validator account $account_name"

   # Generate a password for the account. A base64 string. (and remove the newline from the output)
   account_passphrase=$(openssl rand -base64 32 | tr -d '\n')

   ethdo account create \
      --basedir="$walletbasedir" \
      --account="$account_name" \
      --walletpassphrase="$validator_wallet_passphrase" \
      --passphrase="$account_passphrase"

   echo "\"$account_name\",\"$account_passphrase\"" >> "$account_passwords_csv_file"
done
