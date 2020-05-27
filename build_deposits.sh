#!/bin/bash

echo "USE AT YOUR OWN RISK"
read -p "Are you sure? " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
fi

walletbasedir="./wallets/experiment"
account_passwords_csv_file="./wallets/experiment/val_passwords.csv"

withdrawal_wallet_name="Withdrawal"
withdrawal_account_name="Primary"

forkversion="0x00000113"

amount="32Ether"

deposit_datas_file="deposit_datas.txt"

INPUT=$account_passwords_csv_file
OLDIFS=$IFS
IFS=','
[ ! -f $INPUT ] && { echo "$INPUT file not found"; exit 99; }
while read account_name account_passphrase
do
  account_name=$(echo -n "$account_name" | tr -d '"')
  account_passphrase=$(echo -n "$account_passphrase" | tr -d '"')
	echo "Building deposit for: $account_name"
	# echo "Pass: $account_passphrase"

   x=$(ethdo validator depositdata \
      --basedir="$walletbasedir" \
      --validatoraccount="$account_name" \
      --withdrawalaccount="$withdrawal_wallet_name/$withdrawal_account_name" \
      --depositvalue="$amount" \
      --forkversion="$forkversion" \
      --walletpassphrase="$wallet_passphrase" \
      --passphrase="$account_passphrase")

   echo "$x" >> "$deposit_datas_file"
done < $INPUT
IFS=$OLDIFS


