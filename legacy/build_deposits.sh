#!/bin/bash

echo "USE AT YOUR OWN RISK"
read -p "Are you sure? " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
fi


eth2-val-tools deposit-data \
  --source-min=$ACC_START_INDEX \
  --source-max=$ACC_END_INDEX \
  --amount="$DEPOSIT_AMOUNT" \
  --fork-version="$FORK_VERSION" \
  --withdrawals-mnemonic="$WITHDRAWALS_MNEMONIC" \
  --validators-mnemonic="$VALIDATORS_MNEMONIC" > $DEPOSIT_DATAS_FILE
