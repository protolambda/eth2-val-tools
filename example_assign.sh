mkdir -p example_output/hosts

go run . assign \
  --assignments="example_output/assignments.json" \
  --hostname="morty" \
  --out-loc="example_output/hosts/morty" \
  --source-mnemonic="$VALIDATORS_MNEMONIC" \
  --source-min=0 \
  --source-max=30 \
  --count=20 \
  --config-base-path="/data" \
  --key-man-loc="/data/wallets" \
  --wallet-name="example source wallet name"

go run . assign \
  --assignments="example_output/assignments.json" \
  --hostname="rick" \
  --out-loc="example_output/hosts/rick" \
  --source-mnemonic="$VALIDATORS_MNEMONIC" \
  --source-min=0 \
  --source-max=30 \
  --count=15 \
  --config-base-path="/data" \
  --key-man-loc="/data/wallets" \
  --wallet-name="example source wallet name"

# Rick will only have the 10 remaining accounts assigned.

# cd example_output/hosts && tar -zcvf morty.tar.gz morty/*
