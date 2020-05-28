#!/bin/bash

echo "USE AT YOUR OWN RISK"
read -p "Are you sure? " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
fi

walletbasedir="./wallets/experiment2"
account_passwords_csv_file="./wallets/experiment/val_passwords.csv"

validator_wallet_name="Validators"
validator_wallet_passphrase="lmaolmao"

account_start=1
account_end=10

# TODO: hd type wallet has an ethdo problem with directory location
wallet_type="hierarchical deterministic"
#wallet_type="non-deterministic"

mkdir -p "$walletbasedir"

echo "Creating validator wallet"

# Create wallet
~/go/bin/ethdo wallet create \
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

   ~/go/bin/ethdo account create \
      --basedir="$walletbasedir" \
      --account="$account_name" \
      --walletpassphrase="$validator_wallet_passphrase" \
      --passphrase="$account_passphrase"

   echo "\"$account_name\",\"$account_passphrase\"" >> "$account_passwords_csv_file"
done
