#!/bin/bash

echo "USE AT YOUR OWN RISK"
read -p "Are you sure? " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
fi

# DEPOSIT_CONTRACT_ADDRESS="0x42cc0FcEB02015F145105Cf6f19F90e9BEa76558"
if [[ -z "${DEPOSIT_CONTRACT_ADDRESS}" ]]; then
  echo "need DEPOSIT_CONTRACT_ADDRESS environment var"
  exit 1 || return 1
fi

# Eth1
# ETH1_FROM_ADDR="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
# ETH1_FROM_PRIV="0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

if [[ -z "${ETH1_FROM_ADDR}" ]]; then
  echo "need ETH1_FROM_ADDR environment var"
  exit 1 || return 1
fi
if [[ -z "${ETH1_FROM_PRIV}" ]]; then
  echo "need ETH1_FROM_PRIV environment var"
  exit 1 || return 1
fi

deposit_datas_file="deposit_datas.txt"

# Required for testnets that are not recognized by ethdo
force_deposit=false

eth1_network=goerli

# Iterate through lines, each is a json of the deposit data and some metadata
while read x; do
   # TODO: check validity of deposit before sending it
   account_name = "$(echo "$x" | jq '.account')"
   pubkey = "$(echo "$x" | jq '.pubkey')"
   echo "Sending deposit for validator $account_name $pubkey"
   ~/go/bin/ethereal beacon deposit \
      --address="$DEPOSIT_CONTRACT_ADDRESS" \
      --force=$force_deposit \
      --network=$eth1_network \
      --data="$x" \
      --from="$ETH1_FROM_ADDR" \
      --privatekey="$ETH1_FROM_PRIV"
   echo "Sent deposit for validator $account_name $pubkey"
done < "$deposit_datas_file"


