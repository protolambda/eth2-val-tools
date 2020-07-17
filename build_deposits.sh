#!/bin/bash

echo "USE AT YOUR OWN RISK"
read -p "Are you sure? " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
fi


for ((i=$ACC_START_INDEX;i<$ACC_END_INDEX;i++));
do
  validator_name="$VALIDATORS_WALLET_NAME/$i"
  withdrawal_name="$WITHDRAWALS_WALLET_NAME/$i"
	echo "Building deposit for: $validator_name (withdrawal to $withdrawal_name)"
	# echo "Pass: $account_passphrase"

   x=$(ethdo validator depositdata \
      --basedir="$WALLET_DIR" \
      --validatoraccount="$validator_name" \
      --withdrawalaccount="$withdrawal_name" \
      --depositvalue="$DEPOSIT_AMOUNT" \
      --forkversion="$FORK_VERSION" \
      --walletpassphrase="$VALIDATORS_WALLET_PASSWORD")

   echo "$x" >> "$DEPOSIT_DATAS_FILE"
done
