package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/uuid"
	hbls "github.com/herumi/bls-eth-go-binary/bls"
	"github.com/protolambda/go-keystorev4"
	"github.com/protolambda/zrnt/eth2/beacon"
	"github.com/protolambda/zrnt/eth2/configs"
	"github.com/protolambda/zrnt/eth2/util/hashing"
	"github.com/protolambda/ztyp/tree"
	"github.com/spf13/cobra"
	"github.com/tyler-smith/go-bip39"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	util "github.com/wealdtech/go-eth2-util"
	"golang.org/x/sync/errgroup"
)

func init() {
	hbls.Init(hbls.BLS12_381)
	hbls.SetETHmode(hbls.EthModeLatest)
}

type WalletOutput interface {
	InsertAccount(priv e2types.PrivateKey, insecure bool, idx uint64) error
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
	insecure   bool
}

func NewKeyEntry(priv e2types.PrivateKey, insecure bool) (*KeyEntry, error) {
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
		insecure:   insecure,
	}, nil
}

func (ke *KeyEntry) MarshalJSON() ([]byte, error) {
	var salt [32]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, err
	}
	kdfParams := &keystorev4.PBKDF2Params{
		Dklen: 32,
		C:     262144,
		Prf:   "hmac-sha256",
		Salt:  salt[:],
	}
	if ke.insecure { // INSECURE but much faster, this is useful for ephemeral testnets
		kdfParams.C = 2
	}
	cipherParams, err := keystorev4.NewAES128CTRParams()
	if err != nil {
		return nil, fmt.Errorf("failed to create AES128CTR params: %w", err)
	}
	crypto, err := keystorev4.Encrypt(ke.secretKey.Marshal(), []byte(ke.passphrase),
		kdfParams, keystorev4.Sha256ChecksumParams, cipherParams)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt secret: %w", err)
	}
	keystore := &keystorev4.Keystore{
		Crypto:      *crypto,
		Description: fmt.Sprintf("0x%x", ke.publicKey.Marshal()),
		Pubkey:      ke.publicKey.Marshal(),
		Path:        "",
		UUID:        ke.id,
		Version:     4,
	}
	return json.Marshal(keystore)
}

func (ke *KeyEntry) PubHex() string {
	return "0x" + hex.EncodeToString(ke.publicKey.Marshal())
}

func (ke *KeyEntry) PubHexBare() string {
	return hex.EncodeToString(ke.publicKey.Marshal())
}

type WalletWriter struct {
	sync.RWMutex
	entries []*KeyEntry
}

func NewWalletWriter(entries uint64) *WalletWriter {
	return &WalletWriter{
		entries: make([]*KeyEntry, entries),
	}

}

func (ww *WalletWriter) InsertAccount(priv e2types.PrivateKey, insecure bool, idx uint64) error {
	key, err := NewKeyEntry(priv, insecure)
	if err != nil {
		return err
	}
	ww.RWMutex.Lock()
	defer ww.RWMutex.Unlock()
	ww.entries[idx] = key
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
	// Prysm wallet expects the following structure, assuming
	// the output path is called `prysm`:
	//  direct/
	//    accounts/
	//      all-accounts.keystore.json
	//      - Prysm doesn't know what individual keystores are, only allowing you to import them with CLI, but not simply load them as accounts.
	//      - All pubkeys/privkeys are put in two lists, encoded as JSON, and those bytes are then encrypted exactly like a single private key would be normally
	//      - And then persisted in "all-accounts.keystore.json"
	//  keymanageropts.json
	//  - '{"direct_eip_version": "EIP-2335"}'
	accountsKeystorePath := filepath.Join(outPath, "direct", "accounts")
	if err := os.MkdirAll(accountsKeystorePath, os.ModePerm); err != nil {
		return err
	}
	store := PrysmAccountStore{}
	for _, e := range ww.entries {
		store.PublicKeys = append(store.PublicKeys, e.publicKey.Marshal())
		store.PrivateKeys = append(store.PrivateKeys, e.secretKey.Marshal())
	}
	storeBytes, err := json.MarshalIndent(&store, "", "\t")
	if err != nil {
		return err
	}

	kdfParams, err := keystorev4.NewPBKDF2Params()
	if err != nil {
		return fmt.Errorf("failed to create PBKDF2 params: %w", err)
	}
	cipherParams, err := keystorev4.NewAES128CTRParams()
	if err != nil {
		return fmt.Errorf("failed to create AES128CTR params: %w", err)
	}
	crypto, err := keystorev4.Encrypt(storeBytes, []byte(prysmPass),
		kdfParams, keystorev4.Sha256ChecksumParams, cipherParams)
	if err != nil {
		return fmt.Errorf("failed to encrypt secret: %w", err)
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return err
	}
	keystore := &keystorev4.Keystore{
		Crypto:      *crypto,
		Description: "",
		Pubkey:      nil,
		Path:        "",
		UUID:        id,
		Version:     4,
	}
	encodedStore, err := json.MarshalIndent(keystore, "", "\t")
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(filepath.Join(accountsKeystorePath, "all-accounts.keystore.json"), encodedStore, 0644); err != nil {
		return err
	}
	if err := ioutil.WriteFile(filepath.Join(outPath, "keymanageropts.json"), []byte(`{"direct_eip_version": "EIP-2335"}`), 0644); err != nil {
		return err
	}
	return nil
}

func (ww *WalletWriter) WriteOutputs(fpath string, prysmPass string) error {
	if _, err := os.Stat(fpath); !os.IsNotExist(err) {
		return errors.New("output for assignments already exists! Aborting")
	}
	if err := os.MkdirAll(fpath, os.ModePerm); err != nil {
		return err
	}
	// What lighthouse requires as file name
	lighthouseKeyfileName := "voting-keystore.json"
	lighthouseKeyfilesPath := filepath.Join(fpath, "keys")
	if err := os.Mkdir(lighthouseKeyfilesPath, os.ModePerm); err != nil {
		return err
	}
	// nimbus has different keystore names
	nimbusKeyfileName := "keystore.json"
	nimbusKeyfilesPath := filepath.Join(fpath, "nimbus-keys")
	if err := os.Mkdir(nimbusKeyfilesPath, os.ModePerm); err != nil {
		return err
	}
	// teku does not nest their keystores
	tekuKeyfilesPath := filepath.Join(fpath, "teku-keys")
	if err := os.Mkdir(tekuKeyfilesPath, os.ModePerm); err != nil {
		return err
	}

	var g errgroup.Group
	// For all: write JSON keystore files, each in their own directory (lighthouse requirement)
	for _, k := range ww.entries {
		e := k
		g.Go(func() error {
			dat, err := e.MarshalJSON()
			if err != nil {
				return err
			}
			{
				// lighthouse
				keyDirPath := filepath.Join(lighthouseKeyfilesPath, e.PubHex())
				if err := os.MkdirAll(keyDirPath, os.ModePerm); err != nil {
					return err
				}
				if err := ioutil.WriteFile(filepath.Join(keyDirPath, lighthouseKeyfileName), dat, 0644); err != nil {
					return err
				}
			}
			{
				// nimbus
				keyDirPath := filepath.Join(nimbusKeyfilesPath, e.PubHex())
				if err := os.MkdirAll(keyDirPath, os.ModePerm); err != nil {
					return err
				}
				if err := ioutil.WriteFile(filepath.Join(keyDirPath, nimbusKeyfileName), dat, 0644); err != nil {
					return err
				}
			}
			{
				// teku
				if err := ioutil.WriteFile(filepath.Join(tekuKeyfilesPath, e.PubHex()+".json"), dat, 0644); err != nil {
					return err
				}
			}
			return nil
		})

	}
	{
		// For Lighthouse: they need a directory that maps pubkey to passwords, one per file
		secretsDirPath := filepath.Join(fpath, "secrets")
		if err := os.Mkdir(secretsDirPath, os.ModePerm); err != nil {
			return err
		}
		for _, k := range ww.entries {
			e := k
			g.Go(func() error {
				pubHex := e.PubHex()
				return ioutil.WriteFile(path.Join(secretsDirPath, pubHex), []byte(e.passphrase), 0644)
			})
		}
	}

	{
		// For Teku: they need a directory that maps name of keystore dir to name of secret file, but secret files end with `.txt`
		secretsDirPath := filepath.Join(fpath, "teku-secrets")
		if err := os.Mkdir(secretsDirPath, os.ModePerm); err != nil {
			return err
		}
		for _, k := range ww.entries {
			e := k
			g.Go(func() error {
				pubHex := e.PubHex()
				return ioutil.WriteFile(filepath.Join(secretsDirPath, pubHex+".txt"), []byte(e.passphrase), 0644)
			})

		}
	}

	{
		// For Lodestar: they need a directory that maps pubkey to passwords, one per file, but no 0x prefix.
		secretsDirPath := filepath.Join(fpath, "lodestar-secrets")
		if err := os.Mkdir(secretsDirPath, os.ModePerm); err != nil {
			return err
		}
		for _, k := range ww.entries {
			e := k
			g.Go(func() error {
				pubHex := e.PubHexBare()
				return ioutil.WriteFile(filepath.Join(secretsDirPath, "0x" + pubHex), []byte(e.passphrase), 0644)
			})

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
	if err := ioutil.WriteFile(filepath.Join(fpath, "pubkeys.json"), pubsData, 0644); err != nil {
		return err
	}

	// For Prysm: write outputs as a wallet and a configuration
	if err := ww.buildPrysmWallet(filepath.Join(fpath, "prysm"), prysmPass); err != nil {
		return err
	}
	return g.Wait()
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

func keystoresCommand() *cobra.Command {

	var prysmPass string

	var outputDataPath string

	var sourceMnemonic string

	var accountMin uint64
	var accountMax uint64

	var insecure bool

	cmd := &cobra.Command{
		Use:   "keystores",
		Short: "Build range of keystores for any target format",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			checkErr := makeCheckErr(cmd)

			ww := NewWalletWriter(accountMax - accountMin)
			checkErr(selectVals(sourceMnemonic, accountMin, accountMax, ww, insecure), "failed to assign validators")
			checkErr(ww.WriteOutputs(outputDataPath, prysmPass), "failed to write output")
		},
	}
	cmd.Flags().StringVar(&prysmPass, "prysm-pass", "", "Password for all-accounts keystore file (Prysm only)")

	cmd.Flags().StringVar(&outputDataPath, "out-loc", "assigned_data", "Path of the output data for the host, where wallets, keys, secrets dir, etc. are written")

	cmd.Flags().StringVar(&sourceMnemonic, "source-mnemonic", "", "The validators mnemonic to source account keys from.")

	cmd.Flags().Uint64Var(&accountMin, "source-min", 0, "Minimum validator index in HD path range (incl.)")
	cmd.Flags().Uint64Var(&accountMax, "source-max", 0, "Maximum validator index in HD path range (excl.)")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "Enable to output insecure keystores (faster generation, ONLY for ephemeral private testnets")

	return cmd
}

// Narrow pubkeys: we don't want 0xAb... to be different from ab...
func narrowedPubkey(pub string) string {
	return strings.TrimPrefix(strings.ToLower(pub), "0x")
}

func selectVals(sourceMnemonic string,
	minAcc uint64, maxAcc uint64,
	output WalletOutput, insecure bool) error {

	valSeed, err := mnemonicToSeed(sourceMnemonic)
	if err != nil {
		return err
	}

	var g errgroup.Group
	// Try look for unassigned accounts in the wallet
	for i := minAcc; i < maxAcc; i++ {
		idx := i
		g.Go(func() error {
			valAccPath := fmt.Sprintf("m/12381/3600/%d/0/0", idx)
			a, err := util.PrivateKeyFromSeedAndPath(valSeed, valAccPath)
			if err != nil {
				return fmt.Errorf("account %s cannot be derived, continuing to next account", valAccPath)
			}
			pubkey := narrowedPubkey(hex.EncodeToString(a.PublicKey().Marshal()))
			if err := output.InsertAccount(a, insecure, idx-minAcc); err != nil {
				if err.Error() == fmt.Sprintf("account with name \"%s\" already exists", pubkey) {
					fmt.Printf("Account with pubkey %s already exists in output wallet, skipping it\n", pubkey)
				} else {
					return fmt.Errorf("failed to import account with pubkey %s into output wallet: %v", pubkey, err)
				}
			}

			return nil
		})

	}
	return g.Wait()
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

func mnemonicToSeed(mnemonic string) (seed []byte, err error) {
	mnemonic = strings.TrimSpace(mnemonic)
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.New("mnemonic is not valid")
	}
	return bip39.NewSeed(mnemonic, ""), nil
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

			valSeed, err := mnemonicToSeed(validatorsMnemonic)
			checkErr(err, "bad validator mnemonic")
			withdrSeed, err := mnemonicToSeed(withdrawalsMnemonic)
			checkErr(err, "bad withdrawal mnemonic")

			if asJsonList {
				cmd.Println("[")
			}
			for i := accountMin; i < accountMax; i++ {
				valAccPath := fmt.Sprintf("m/12381/3600/%d/0/0", i)
				val, err := util.PrivateKeyFromSeedAndPath(valSeed, valAccPath)
				checkErr(err, fmt.Sprintf("failed to create validator private key for path %q", valAccPath))
				withdrAccPath := fmt.Sprintf("m/12381/3600/%d/0", i)
				withdr, err := util.PrivateKeyFromSeedAndPath(withdrSeed, withdrAccPath)
				checkErr(err, fmt.Sprintf("failed to create withdrawal private key for path %q", withdrAccPath))

				var pub beacon.BLSPubkey
				copy(pub[:], val.PublicKey().Marshal())

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
				checkErr(err, "cannot get validator private key")
				var secKey hbls.SecretKey
				checkErr(secKey.Deserialize(val.Marshal()), "cannot convert validator priv key")

				dom := beacon.ComputeDomain(configs.Mainnet.DOMAIN_DEPOSIT, genesisForkVersion, beacon.Root{})
				msg := beacon.ComputeSigningRoot(msgRoot, dom)
				sig := secKey.SignHash(msg[:])
				copy(data.Signature[:], sig.Serialize())

				dataRoot := data.HashTreeRoot(tree.GetHashFn())
				jsonData := map[string]interface{}{
					"account":                valAccPath, // for ease with tracking where it came from.
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

			valSeed, err := mnemonicToSeed(validatorsMnemonic)
			checkErr(err, "bad validator mnemonic")

			for i := accountMin; i < accountMax; i++ {

				path := fmt.Sprintf("m/12381/3600/%d/0/0", i)
				valPrivateKey, err := util.PrivateKeyFromSeedAndPath(valSeed, path)
				checkErr(err, fmt.Sprintf("failed to create validator private key for path %q", path))

				var pub beacon.BLSPubkey
				copy(pub[:], valPrivateKey.PublicKey().Marshal())
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
