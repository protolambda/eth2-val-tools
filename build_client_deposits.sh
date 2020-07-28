#!/bin/bash
echo "USE AT YOUR OWN RISK"
read -p "Are you sure? " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
fi

# Iterate through lines, each is a json of the deposit data and some metadata
account=0
while read x; do
   withdrawal_creds=$(echo "$x" | jq -r '.withdrawal_credentials')
   eth2-val-tools deposit-data-with-withdrawal-creds \
      --account=$account \
      --withdrawal-creds=$withdrawal_creds \
      --validators-mnemonic="$VALIDATORS_MNEMONIC" \
      --fork-version="$FORK_VERSION" >> $DEPOSIT_DATAS_FILE
   account=$(( $account + 1 ))
done < "$WITHDRAWAL_CREDS_FILE"

