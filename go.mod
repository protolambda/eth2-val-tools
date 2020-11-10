module github.com/protolambda/eth2-val-tools

go 1.14

require (
	github.com/MichaelS11/go-file-lock v0.1.0
	github.com/aws/aws-sdk-go v1.35.21 // indirect
	github.com/ferranbt/fastssz v0.0.0-20201030134205-9b9624098321 // indirect
	github.com/google/uuid v1.1.2
	github.com/herumi/bls-eth-go-binary v0.0.0-20201104034342-d782bdf735de
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/protolambda/zrnt v0.12.5
	github.com/protolambda/ztyp v0.1.1
	github.com/spf13/cobra v1.1.1
	github.com/tyler-smith/go-bip39 v1.1.0
	github.com/wealdtech/go-eth2-types/v2 v2.5.1
	github.com/wealdtech/go-eth2-wallet v1.14.2
	github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4 v1.1.2
	github.com/wealdtech/go-eth2-wallet-hd/v2 v2.5.2
	github.com/wealdtech/go-eth2-wallet-store-filesystem v1.16.13
	github.com/wealdtech/go-eth2-wallet-store-scratch v1.6.1
	github.com/wealdtech/go-eth2-wallet-types/v2 v2.8.1
	golang.org/x/sys v0.0.0-20201101102859-da207088b7d1 // indirect
	golang.org/x/text v0.3.4 // indirect
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f // indirect
	gopkg.in/yaml.v2 v2.3.0
)

replace (
	github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4 => ../go-eth2-wallet-encryptor-keystorev4
)
