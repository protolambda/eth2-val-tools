package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	hbls "github.com/herumi/bls-eth-go-binary/bls"
	"github.com/protolambda/zrnt/eth2/beacon"
	"github.com/protolambda/zrnt/eth2/configs"
	"github.com/protolambda/zrnt/eth2/util/hashing"
	"github.com/protolambda/ztyp/tree"
	"github.com/spf13/cobra"
	"github.com/tyler-smith/go-bip39"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	hd "github.com/wealdtech/go-eth2-wallet-hd/v2"
	scratch "github.com/wealdtech/go-eth2-wallet-store-scratch"
	types "github.com/wealdtech/go-eth2-wallet-types/v2"
	"io/ioutil"
	"os"
	"path"
	"strings"
)

func init() {
	hbls.Init(hbls.BLS12_381)
	hbls.SetETHmode(hbls.EthModeLatest)
}

func validatorKeyName(i uint64) string {
	return fmt.Sprintf("m/12381/3600/%d/0/0", i)
}

type WalletOutput interface {
	InsertAccount(priv e2types.PrivateKey) error
}

// Following EIP 2335
type KeyFile struct {
	id        uuid.UUID
	name      string
	publicKey e2types.PublicKey
	secretKey e2types.PrivateKey
}

type KeyEntry struct {
	KeyFile
	passphrase string
}

func NewKeyEntry(priv e2types.PrivateKey) (*KeyEntry, error) {
	var pass [32]byte
	n, err := rand.Read(pass[:])
	if err != nil {
		return nil, err
	}
	if n != 32 {
		return nil, errors.New("could not read sufficient secure random bytes")
	}
	// Convert it to human readable characters, to keep it manageable
	passphrase := base64.URLEncoding.EncodeToString(pass[:])
	return &KeyEntry{
		KeyFile: KeyFile{
			id:        uuid.New(),
			name:      "val_" + hex.EncodeToString(priv.PublicKey().Marshal()),
			publicKey: priv.PublicKey(),
			secretKey: priv,
		},
		passphrase: passphrase,
	}, nil
}

func (ke *KeyEntry) MarshalJSON() ([]byte, error) {
	data := make(map[string]interface{})
	// TODO: ligthouse can't handle this field, should it be here?
	//data["name"] = ke.name
	encryptor := keystorev4.New(keystorev4.WithCipher("pbkdf2"))
	var err error
	data["crypto"], err = encryptor.Encrypt(ke.secretKey.Marshal(), ke.passphrase)
	if err != nil {
		return nil, err
	}
	// Empty, on distributed wallets we do not need it.
	// Teku does not put anything here, and lighthouse has passing tests with empty value here.
	data["path"] = ""
	data["uuid"] = ke.id.String()
	data["version"] = 4
	data["pubkey"] = fmt.Sprintf("%x", ke.publicKey.Marshal())
	return json.Marshal(data)
}

func (ke *KeyEntry) PubHex() string {
	return "0x" + hex.EncodeToString(ke.publicKey.Marshal())
}

func (ke *KeyEntry) PubHexBare() string {
	return hex.EncodeToString(ke.publicKey.Marshal())
}

type WalletWriter struct {
	entries []*KeyEntry
}

func (ww *WalletWriter) InsertAccount(priv e2types.PrivateKey) error {
	key, err := NewKeyEntry(priv)
	if err != nil {
		return err
	}
	ww.entries = append(ww.entries, key)
	return nil
}

type PrysmAccountStore struct {
	PrivateKeys [][]byte `json:"private_keys"`
	PublicKeys  [][]byte `json:"public_keys"`
}

func (ww *WalletWriter) buildPrysmWallet(outPath string, prysmPass string) error {
	if err := os.MkdirAll(outPath, os.ModePerm); err != nil {
		return err
	}
	// a directory called "direct"
	//  - keymanageropts.json
	//      '{"direct_eip_version": "EIP-2335"}'
	//  - all-accounts.keystore.json
	//    - Prysm doesn't know what individual keystores are, only allowing you to import them with CLI, but not simply load them as accounts.
	//    - All pubkeys/privkeys are put in two lists, encoded as JSON, and those bytes are then encrypted exactly like a single private key would be normally
	//    - And then persisted in "all-accounts.keystore.json"

	store := PrysmAccountStore{}
	for _, e := range ww.entries {
		store.PublicKeys = append(store.PublicKeys, e.publicKey.Marshal())
		store.PrivateKeys = append(store.PrivateKeys, e.secretKey.Marshal())
	}
	storeBytes, err := json.MarshalIndent(&store, "", "\t")
	if err != nil {
		return err
	}
	encryptor := keystorev4.New()
	id, err := uuid.NewRandom()
	if err != nil {
		return err
	}
	cryptoFields, err := encryptor.Encrypt(storeBytes, prysmPass)
	if err != nil {
		return err
	}
	data := make(map[string]interface{})
	data["uuid"] = id.String()
	data["version"] = 4
	data["crypto"] = cryptoFields
	encodedStore, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(path.Join(outPath, "all-accounts.keystore.json"), encodedStore, 0644); err != nil {
		return err
	}
	if err := ioutil.WriteFile(path.Join(outPath, "keymanageropts.json"), []byte(`{"direct_eip_version": "EIP-2335"}`), 0644); err != nil {
		return err
	}
	return nil
}

func (ww *WalletWriter) WriteOutputs(filepath string, prysmPass string) error {
	if _, err := os.Stat(filepath); !os.IsNotExist(err) {
		return errors.New("output for assignments already exists! Aborting")
	}
	if err := os.MkdirAll(filepath, os.ModePerm); err != nil {
		return err
	}
	// What lighthouse requires as file name
	lighthouseKeyfileName := "voting-keystore.json"
	lighthouseKeyfilesPath := path.Join(filepath, "keys")
	if err := os.Mkdir(lighthouseKeyfilesPath, os.ModePerm); err != nil {
		return err
	}
	// nimbus has different keystore names
	nimbusKeyfileName := "keystore.json"
	nimbusKeyfilesPath := path.Join(filepath, "nimbus-keys")
	if err := os.Mkdir(nimbusKeyfilesPath, os.ModePerm); err != nil {
		return err
	}
	// teku does not nest their keystores
	tekuKeyfilesPath := path.Join(filepath, "teku-keys")
	if err := os.Mkdir(tekuKeyfilesPath, os.ModePerm); err != nil {
		return err
	}
	// For all: write JSON keystore files, each in their own directory (lighthouse requirement)
	for _, e := range ww.entries {
		dat, err := e.MarshalJSON()
		if err != nil {
			return err
		}
		{
			// lighthouse
			keyDirPath := path.Join(lighthouseKeyfilesPath, e.PubHex())
			if err := os.MkdirAll(keyDirPath, os.ModePerm); err != nil {
				return err
			}
			if err := ioutil.WriteFile(path.Join(keyDirPath, lighthouseKeyfileName), dat, 0644); err != nil {
				return err
			}
		}
		{
			// nimbus
			keyDirPath := path.Join(nimbusKeyfilesPath, e.PubHex())
			if err := os.MkdirAll(keyDirPath, os.ModePerm); err != nil {
				return err
			}
			if err := ioutil.WriteFile(path.Join(keyDirPath, nimbusKeyfileName), dat, 0644); err != nil {
				return err
			}
		}
		{
			// teku
			if err := ioutil.WriteFile(path.Join(tekuKeyfilesPath, e.PubHex()+".json"), dat, 0644); err != nil {
				return err
			}
		}
	}
	{
		// For Lighthouse: they need a directory that maps pubkey to passwords, one per file
		secretsDirPath := path.Join(filepath, "secrets")
		if err := os.Mkdir(secretsDirPath, os.ModePerm); err != nil {
			return err
		}
		for _, e := range ww.entries {
			pubHex := e.PubHex()
			if err := ioutil.WriteFile(path.Join(secretsDirPath, pubHex), []byte(e.passphrase), 0644); err != nil {
				return err
			}
		}
	}

	{
		// For Teku: they need a directory that maps name of keystore dir to name of secret file, but secret files end with `.txt`
		secretsDirPath := path.Join(filepath, "teku-secrets")
		if err := os.Mkdir(secretsDirPath, os.ModePerm); err != nil {
			return err
		}
		for _, e := range ww.entries {
			pubHex := e.PubHex()
			if err := ioutil.WriteFile(path.Join(secretsDirPath, pubHex+".txt"), []byte(e.passphrase), 0644); err != nil {
				return err
			}
		}
	}

	{
		// For Lodestar: they need a directory that maps pubkey to passwords, one per file, but no 0x prefix.
		secretsDirPath := path.Join(filepath, "lodestar-secrets")
		if err := os.Mkdir(secretsDirPath, os.ModePerm); err != nil {
			return err
		}
		for _, e := range ww.entries {
			pubHex := e.PubHexBare()
			if err := ioutil.WriteFile(path.Join(secretsDirPath, pubHex), []byte(e.passphrase), 0644); err != nil {
				return err
			}
		}
	}

	// In general: a list of pubkeys.
	pubkeys := make([]string, 0)
	for _, e := range ww.entries {
		pubkeys = append(pubkeys, e.PubHex())
	}
	pubsData, err := json.Marshal(pubkeys)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(path.Join(filepath, "pubkeys.json"), pubsData, 0644); err != nil {
		return err
	}

	// For Prysm: write outputs as a wallet and a configuration
	if err := ww.buildPrysmWallet(path.Join(filepath, "prysm"), prysmPass); err != nil {
		return err
	}
	return nil
}

func makeCheckErr(cmd *cobra.Command) func(err error, msg string) {
	return func(err error, msg string) {
		if err != nil {
			if msg != "" {
				err = fmt.Errorf("%s: %v", msg, err)
			}
			cmd.PrintErr(err)
			os.Exit(1)
		}
	}
}

func walletFromMnemonic(mnemonic string) (types.Wallet, error) {
	store := scratch.New()
	encryptor := keystorev4.New()
	mnemonic = strings.TrimSpace(mnemonic)
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.New("mnemonic is not valid")
	}
	seed := bip39.NewSeed(mnemonic, "")
	wallet, err := hd.CreateWallet(context.Background(), "imported wallet", []byte{}, store, encryptor, seed)
	if err != nil {
		return nil, fmt.Errorf("failed to create scratch wallet from seed: %v", err)
	}
	err = wallet.(types.WalletLocker).Unlock(context.Background(), []byte{})
	if err != nil {
		return nil, fmt.Errorf("failed to unlock scratch wallet: %v", err)
	}
	return wallet, nil
}

func keystoresCommand() *cobra.Command {

	var prysmPass string

	var outputDataPath string

	var sourceMnemonic string

	var accountMin uint64
	var accountMax uint64

	cmd := &cobra.Command{
		Use:   "keystores",
		Short: "Build range of keystores for any target format",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			checkErr := makeCheckErr(cmd)
			wallet, err := walletFromMnemonic(sourceMnemonic)
			checkErr(err, "could not create scratch wallet from mnemonic")

			walletProv := wallet.(types.WalletAccountByNameProvider)

			ww := &WalletWriter{}
			checkErr(selectVals(context.Background(), walletProv, accountMin, accountMax, ww), "failed to assign validators")
			checkErr(ww.WriteOutputs(outputDataPath, prysmPass), "failed to write output")
		},
	}
	cmd.Flags().StringVar(&prysmPass, "prysm-pass", "", "Password for all-accounts keystore file (Prysm only)")

	cmd.Flags().StringVar(&outputDataPath, "out-loc", "assigned_data", "Path of the output data for the host, where wallets, keys, secrets dir, etc. are written")

	cmd.Flags().StringVar(&sourceMnemonic, "source-mnemonic", "", "The validators mnemonic to source account keys from.")

	cmd.Flags().Uint64Var(&accountMin, "source-min", 0, "Minimum validator index in HD path range (incl.)")
	cmd.Flags().Uint64Var(&accountMax, "source-max", 0, "Maximum validator index in HD path range (excl.)")

	return cmd
}

// Narrow pubkeys: we don't want 0xAb... to be different from ab...
func narrowedPubkey(pub string) string {
	return strings.TrimPrefix(strings.ToLower(pub), "0x")
}

func selectVals(ctx context.Context,
	wallet types.WalletAccountByNameProvider,
	minAcc uint64, maxAcc uint64,
	output WalletOutput) error {

	// Try look for unassigned accounts in the wallet
	for i := minAcc; i < maxAcc; i++ {
		name := validatorKeyName(i)
		a, err := wallet.AccountByName(ctx, name)
		if err != nil {
			fmt.Printf("Account %s cannot be opened, continuing to next account.\n", name)
			continue
		}
		pubkey := narrowedPubkey(hex.EncodeToString(a.PublicKey().Marshal()))
		if aLocked, ok := a.(types.AccountLocker); ok {
			if err := aLocked.Unlock(ctx, []byte{}); err != nil {
				return fmt.Errorf("failed to unlock priv key for account %s with pubkey %s: %v", a.ID().String(), pubkey, err)
			}
		}
		aPriv, ok := a.(types.AccountPrivateKeyProvider)
		if !ok {
			return fmt.Errorf("cannot get priv key for account %s with pubkey %s", a.ID().String(), pubkey)
		}
		priv, err := aPriv.PrivateKey(ctx)
		if err != nil {
			return fmt.Errorf("cannot read priv key for account %s with pubkey %s: %v", a.ID().String(), pubkey, err)
		}
		if err := output.InsertAccount(priv); err != nil {
			if err.Error() == fmt.Sprintf("account with name \"%s\" already exists", pubkey) {
				fmt.Printf("Account with pubkey %s already exists in output wallet, skipping it\n", pubkey)
			} else {
				return fmt.Errorf("failed to import account %s with pubkey %s into output wallet: %v", a.ID().String(), pubkey, err)
			}
		}
	}
	return nil
}

func createMnemonicCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mnemonic",
		Short: "Create a random mnemonic",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			checkErr := makeCheckErr(cmd)
			entropy, err := bip39.NewEntropy(256)
			checkErr(err, "cannot get 256 bits of entropy")
			mnemonic, err := bip39.NewMnemonic(entropy)
			checkErr(err, "cannot create mnemonic")
			cmd.Print(mnemonic)
		},
	}
	return cmd
}

func createDepositDatasCmd() *cobra.Command {
	var accountMin uint64
	var accountMax uint64

	var amountGwei uint64

	var forkVersion string

	var validatorsMnemonic string
	var withdrawalsMnemonic string

	var asJsonList bool

	cmd := &cobra.Command{
		Use:   "deposit-data",
		Short: "Create deposit data for the given range of validators. 1 json-encoded deposit data per line.",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			checkErr := makeCheckErr(cmd)
			var genesisForkVersion beacon.Version
			checkErr(genesisForkVersion.UnmarshalText([]byte(forkVersion)), "cannot decode fork version")
			validators, err := walletFromMnemonic(validatorsMnemonic)
			checkErr(err, "failed to load validators mnemonic")
			valAccs := validators.(types.WalletAccountByNameProvider)
			withdrawals, err := walletFromMnemonic(withdrawalsMnemonic)
			checkErr(err, "failed to load validators mnemonic")
			withdrawlAccs := withdrawals.(types.WalletAccountByNameProvider)
			ctx := context.Background()
			if asJsonList {
				cmd.Println("[")
			}
			for i := accountMin; i < accountMax; i++ {
				accPath := validatorKeyName(i)
				val, err := valAccs.AccountByName(ctx, accPath)
				checkErr(err, fmt.Sprintf("could not get validator key %d", i))

				var pub beacon.BLSPubkey
				copy(pub[:], val.PublicKey().Marshal())

				withdr, err := withdrawlAccs.AccountByName(ctx, accPath)
				checkErr(err, fmt.Sprintf("could not get withdrawl key %d", i))

				var withdrPub beacon.BLSPubkey
				copy(withdrPub[:], withdr.PublicKey().Marshal())
				withdrCreds := hashing.Hash(withdrPub[:])
				withdrCreds[0] = configs.Mainnet.BLS_WITHDRAWAL_PREFIX[0]

				data := beacon.DepositData{
					Pubkey:                pub,
					WithdrawalCredentials: withdrCreds,
					Amount:                beacon.Gwei(amountGwei),
					Signature:             beacon.BLSSignature{},
				}
				msgRoot := data.ToMessage().HashTreeRoot(tree.GetHashFn())
				valPriv, err := val.(types.AccountPrivateKeyProvider).PrivateKey(ctx)
				checkErr(err, "cannot get validator private key")
				var secKey hbls.SecretKey
				checkErr(secKey.Deserialize(valPriv.Marshal()), "cannot convert validator priv key")

				dom := beacon.ComputeDomain(configs.Mainnet.DOMAIN_DEPOSIT, genesisForkVersion, beacon.Root{})
				msg := beacon.ComputeSigningRoot(msgRoot, dom)
				sig := secKey.SignHash(msg[:])
				copy(data.Signature[:], sig.Serialize())

				dataRoot := data.HashTreeRoot(tree.GetHashFn())
				jsonData := map[string]interface{}{
					"account":                accPath, // for ease with tracking where it came from.
					"pubkey":                 hex.EncodeToString(data.Pubkey[:]),
					"withdrawal_credentials": hex.EncodeToString(data.WithdrawalCredentials[:]),
					"signature":              hex.EncodeToString(data.Signature[:]),
					"value":                  uint64(data.Amount),
					"deposit_data_root":      hex.EncodeToString(dataRoot[:]),
					"version":                1, // ethereal cli requirement
				}
				jsonStr, err := json.Marshal(jsonData)
				if asJsonList && i+1 < accountMax {
					jsonStr = append(jsonStr, ',')
				}
				checkErr(err, "could not encode deposit data to json")
				cmd.Println(string(jsonStr))
			}
			if asJsonList {
				cmd.Println("]")
			}
		},
	}

	cmd.Flags().StringVar(&validatorsMnemonic, "validators-mnemonic", "", "Mnemonic to use for validators.")
	cmd.Flags().StringVar(&withdrawalsMnemonic, "withdrawals-mnemonic", "", "Mnemonic to use for withdrawals. Withdrawal accounts are assumed to have matching paths with validators.")
	cmd.Flags().Uint64Var(&accountMin, "source-min", 0, "Minimum validator index in HD path range (incl.)")
	cmd.Flags().Uint64Var(&accountMax, "source-max", 0, "Maximum validator index in HD path range (excl.)")
	cmd.Flags().Uint64Var(&amountGwei, "amount", uint64(configs.Mainnet.MAX_EFFECTIVE_BALANCE), "Amount to deposit, in Gwei")
	cmd.Flags().StringVar(&forkVersion, "fork-version", "", "Fork version, e.g. 0x11223344")
	cmd.Flags().BoolVar(&asJsonList, "as-json-list", false, "If the json datas should be wrapped with brackets and separated with commas, like a json list.")

	return cmd
}

func createPubkeysCmd() *cobra.Command {
	var accountMin uint64
	var accountMax uint64

	var validatorsMnemonic string

	cmd := &cobra.Command{
		Use:   "pubkeys",
		Short: "List pubkeys of the given range of validators. Output encoded as one pubkey per line.",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			checkErr := makeCheckErr(cmd)
			validators, err := walletFromMnemonic(validatorsMnemonic)
			checkErr(err, "failed to load validators mnemonic")
			valAccs := validators.(types.WalletAccountByNameProvider)
			ctx := context.Background()
			for i := accountMin; i < accountMax; i++ {
				accPath := validatorKeyName(i)
				val, err := valAccs.AccountByName(ctx, accPath)
				checkErr(err, fmt.Sprintf("could not get validator key %d", i))

				var pub beacon.BLSPubkey
				copy(pub[:], val.PublicKey().Marshal())
				cmd.Println(pub.String())
			}
		},
	}
	cmd.Flags().StringVar(&validatorsMnemonic, "validators-mnemonic", "", "Mnemonic to use for validators.")
	cmd.Flags().Uint64Var(&accountMin, "source-min", 0, "Minimum validator index in HD path range (incl.)")
	cmd.Flags().Uint64Var(&accountMax, "source-max", 0, "Maximum validator index in HD path range (excl.)")
	return cmd
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "eth2-val-tools",
		Short: "Manage Eth2 validator assignments - USE AT YOUR OWN RISK",
		Long:  `Manage Eth2 validator assignments for automated deployments, built by @protolambda.`,
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}
	rootCmd.AddCommand(keystoresCommand())
	rootCmd.AddCommand(createMnemonicCmd())
	rootCmd.AddCommand(createDepositDatasCmd())
	rootCmd.AddCommand(createPubkeysCmd())
	rootCmd.SetOut(os.Stdout)
	rootCmd.SetErr(os.Stderr)
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
