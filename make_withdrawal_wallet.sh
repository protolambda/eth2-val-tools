#!/bin/bash

echo "USE AT YOUR OWN RISK"
read -p "Are you sure? " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
fi

mkdir -p "$WALLET_DIR"

echo "Creating withdrawal wallet"

# Create wallet
~/go/bin/ethdo wallet create \
   --type="hierarchical deterministic" \
   --debug=true \
   --basedir="$WALLET_DIR" \
   --wallet="$WITHDRAWALS_WALLET_NAME" \
   --walletpassphrase="$WITHDRAWALS_WALLET_PASSWORD"

for ((i=$ACC_START_INDEX;i<$ACC_END_INDEX;i++));
do
   account_name="$WITHDRAWALS_WALLET_NAME/$i"
   echo "Creating withdrawal account $account_name"

   ~/go/bin/ethdo account create \
      --basedir="$WALLET_DIR" \
      --account="$account_name" \
      --store="filesystem" \
      --walletpassphrase="$WITHDRAWALS_WALLET_PASSWORD"

done
