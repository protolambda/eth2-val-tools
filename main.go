package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	filelock "github.com/MichaelS11/go-file-lock"
	"github.com/google/uuid"
	hbls "github.com/herumi/bls-eth-go-binary/bls"
	"github.com/protolambda/zrnt/eth2/beacon"
	"github.com/protolambda/zrnt/eth2/configs"
	"github.com/protolambda/zrnt/eth2/util/hashing"
	"github.com/protolambda/ztyp/tree"
	"github.com/spf13/cobra"
	"github.com/tyler-smith/go-bip39"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	e2wallet "github.com/wealdtech/go-eth2-wallet"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	hd "github.com/wealdtech/go-eth2-wallet-hd/v2"
	filesystem "github.com/wealdtech/go-eth2-wallet-store-filesystem"
	scratch "github.com/wealdtech/go-eth2-wallet-store-scratch"
	types "github.com/wealdtech/go-eth2-wallet-types/v2"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

func init() {
	hbls.Init(hbls.BLS12_381)
	hbls.SetETHmode(hbls.EthModeLatest)
}

func validatorKeyName(i uint64) string {
	return fmt.Sprintf("m/12381/3600/%d/0/0", i)
}

type ValidatorAssignEntry struct {
	// Pubkey of validator, must be unique across store for current assignments
	Pubkey string `json:"pubkey"`
	// Host is the current remote assignment of the validator
	Host string `json:"host"`
	// Time of assignment
	Time string `json:"assignment_time"`
	// Path, the account path, e.g. "m/12381/3600/123/0/0"
	Path string `json:"path"`
	// WalletName, Where the account comes from
	WalletName string
}

type ValidatorAssignments struct {
	// Historical assignments. Never forget where a key was hosted, unless manually removed.
	// Important for troubleshooting and debugging
	HistoricalAssignments []ValidatorAssignEntry `json:"historical_assignments"`
	// CurrentAssignments is an array instead of a map, to avoid random sorting
	CurrentAssignments []ValidatorAssignEntry `json:"current_assignments"`
}

type AssignmentsView struct {
	Assignments *ValidatorAssignments
	filepath    string
	lock        *filelock.LockHandle
}

func (v *AssignmentsView) Unlock() error {
	return v.lock.Unlock()
}

func (v *AssignmentsView) Write() error {
	// avoid writing null, just write empty lists
	if v.Assignments.HistoricalAssignments == nil {
		v.Assignments.HistoricalAssignments = make([]ValidatorAssignEntry, 0)
	}
	if v.Assignments.CurrentAssignments == nil {
		v.Assignments.CurrentAssignments = make([]ValidatorAssignEntry, 0)
	}
	data, err := json.Marshal(v.Assignments)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(v.filepath, data, 0644)
}

func LoadAssignments(filepath string) (*AssignmentsView, error) {
	// acquire file lock over assignments, we need to be very strict about not double writing, or reading concurrently
	var lock *filelock.LockHandle
	for {
		var err error
		lock, err = filelock.New(filepath + ".lock")
		if err != nil && err == filelock.ErrFileIsBeingUsed {
			time.Sleep(time.Second * 2)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("failed to acquire lock: %v", err)
		}
		break
	}

	var obj ValidatorAssignments
	f, err := os.OpenFile(filepath, os.O_RDONLY|os.O_CREATE, 0644)
	if err != nil {
		_ = lock.Unlock()
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		_ = lock.Unlock()
		return nil, err
	}
	if st.IsDir() {
		_ = lock.Unlock()
		return nil, errors.New("assignments is dir, invalid usage")
	}
	if st.Size() > 0 {
		dec := json.NewDecoder(f)
		if err := dec.Decode(&obj); err != nil {
			_ = lock.Unlock()
			return nil, err
		}
	} else {
		//os.Exit(1)
	}
	return &AssignmentsView{
		Assignments: &obj,
		filepath:    filepath,
		lock:        lock,
	}, nil
}

func storeWithOptions(pass string, loc string) types.Store {
	storeOpts := make([]filesystem.Option, 0)
	if pass != "" {
		storeOpts = append(storeOpts, filesystem.WithPassphrase([]byte(pass)))
	}
	if loc != "" {
		storeOpts = append(storeOpts, filesystem.WithLocation(loc))
	}
	return filesystem.New(storeOpts...)
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

type KeyManagerOpts struct {
	Location    string   `json:"location"`
	Accounts    []string `json:"accounts"`
	Passphrases []string `json:"passphrases"`
}

func (ww *WalletWriter) buildPrysmWallet(outPath string, keyMngWalletLoc string) error {

	// a directory called "direct"
	//  - keymanager_opts.json
	//      '{"direct_eip_version": "EIP-2335"}'
	//  - all-accounts.keystore.json
	//    - Prysm doesn't know what individual keystores are, only allowing you to import them with CLI, but not simply load them as accounts.
	//    - All pubkeys/privkeys are put in two lists, encoded as JSON, and those bytes are then encrypted exactly like a single private key would be normally
	//    - And then persisted in "all-accounts.keystore.json"

	ndStorePath := path.Join(outPath, "wallets")
	walletName := "Assigned"
	outWal, err := e2wallet.CreateWallet(walletName,
		e2wallet.WithStore(filesystem.New(filesystem.WithLocation(ndStorePath))),
		e2wallet.WithType("nd"))
	if err != nil {
		return err
	}
	// nd wallets always unlock
	_ = outWal.(types.WalletLocker).Unlock(context.Background(), nil)
	outWallet := outWal.(types.WalletAccountImporter)
	for _, e := range ww.entries {
		if _, err := outWallet.ImportAccount(context.Background(), e.name, e.secretKey.Marshal(), []byte(e.passphrase)); err != nil {
			return err
		}
	}

	// write a json configuration to specify accounts and passwords
	keyManagerOpts := KeyManagerOpts{Location: keyMngWalletLoc}
	for _, e := range ww.entries {
		keyManagerOpts.Passphrases = append(keyManagerOpts.Passphrases, e.passphrase)
	}
	// TODO: temporary hack, we should change to keystore-centric approach.
	// The prysm account matching of ethdo account names seems broken, use just the wallet name as a catch-all instead.
	keyManagerOpts.Accounts = append(keyManagerOpts.Accounts, walletName)
	optsData, err := json.Marshal(&keyManagerOpts)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(path.Join(outPath, "keymanager_opts.json"), optsData, 0644); err != nil {
		return err
	}
	return nil
}

type TekuConfig struct {
	ValidatorsKeyFiles      []string `yaml:"validators-key-files"`
	ValidatorsPasswordFiles []string `yaml:"validators-key-password-files"`
}

func (ww *WalletWriter) WriteOutputs(filepath string, keyMngWalletLoc string, configBasePath string) error {
	if _, err := os.Stat(filepath); !os.IsNotExist(err) {
		return errors.New("output for assignments already exists! Aborting")
	}
	if err := os.MkdirAll(filepath, os.ModePerm); err != nil {
		return err
	}
	// What lighthouse requires as file name
	keyfileName := "voting-keystore.json"
	keyfilesPath := path.Join(filepath, "keys")
	if err := os.Mkdir(keyfilesPath, os.ModePerm); err != nil {
		return err
	}
	// For all: write JSON keystore files, each in their own directory (lighthouse requirement)
	for _, e := range ww.entries {
		keyDirPath := path.Join(keyfilesPath, e.PubHex())
		if err := os.MkdirAll(keyDirPath, os.ModePerm); err != nil {
			return err
		}
		dat, err := e.MarshalJSON()
		if err != nil {
			return err
		}
		if err := ioutil.WriteFile(path.Join(keyDirPath, keyfileName), dat, 0644); err != nil {
			return err
		}
	}
	{
		// nimbus has different keystore names
		keyfileName := "keystore.json"
		keyfilesPath := path.Join(filepath, "nimbus-keys")
		if err := os.Mkdir(keyfilesPath, os.ModePerm); err != nil {
			return err
		}
		// For all: write JSON keystore files, each in their own directory
		for _, e := range ww.entries {
			keyDirPath := path.Join(keyfilesPath, e.PubHex())
			if err := os.MkdirAll(keyDirPath, os.ModePerm); err != nil {
				return err
			}
			dat, err := e.MarshalJSON()
			if err != nil {
				return err
			}
			if err := ioutil.WriteFile(path.Join(keyDirPath, keyfileName), dat, 0644); err != nil {
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

	// For Teku: a yaml config file pointing to each key and secret
	tekuConfig := TekuConfig{
		ValidatorsKeyFiles:      make([]string, 0), // we don't want null arrays
		ValidatorsPasswordFiles: make([]string, 0),
	}
	for _, e := range ww.entries {
		tekuConfig.ValidatorsKeyFiles = append(tekuConfig.ValidatorsKeyFiles, path.Join(configBasePath, "keys", e.PubHex(), keyfileName))
		tekuConfig.ValidatorsPasswordFiles = append(tekuConfig.ValidatorsPasswordFiles, path.Join(configBasePath, "secrets", e.PubHex()))
	}
	tekuConfData, err := yaml.Marshal(&tekuConfig)
	if err := ioutil.WriteFile(path.Join(filepath, "teku_validators_config.yaml"), tekuConfData, 0644); err != nil {
		return err
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
	if err := ww.buildPrysmWallet(path.Join(filepath, "prysm"), keyMngWalletLoc); err != nil {
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

func assignCommand() *cobra.Command {

	var keyMngWalletLoc string
	var configBasePath string

	var outputDataPath string

	var sourceMnemonic string

	var accountMin uint64
	var accountMax uint64

	var assignmentsLoc string
	var hostname string
	var count uint64
	var addCount bool

	var walletName string

	cmd := &cobra.Command{
		Use:   "assign",
		Short: "Assign `n` available validators to `hostname`. If --add is true, it will add `n` assigned validators, instead of filling up to `n` total assigned to the host",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			checkErr := makeCheckErr(cmd)
			wallet, err := walletFromMnemonic(sourceMnemonic)
			checkErr(err, "could not create scratch wallet from mnemonic")

			ww := &WalletWriter{}
			checkErr(assignVals(context.Background(), wallet.(types.WalletAccountByNameProvider), walletName,
				accountMin, accountMax, ww, assignmentsLoc, hostname, count, addCount), "failed to assign validators")
			checkErr(ww.WriteOutputs(outputDataPath, keyMngWalletLoc, configBasePath), "failed to write output")
		},
	}
	cmd.Flags().StringVar(&keyMngWalletLoc, "key-man-loc", "", "Location to write to the 'location' field in the keymanager_opts.json file (Prysm only)")
	cmd.Flags().StringVar(&configBasePath, "config-base-path", "/data", "Location to use as base in the config file (Teku only)")

	cmd.Flags().StringVar(&outputDataPath, "out-loc", "assigned_data", "Path of the output data for the host, where wallets, keys, secrets dir, etc. are written")

	cmd.Flags().StringVar(&sourceMnemonic, "source-mnemonic", "", "The validators mnemonic to source account keys from")

	cmd.Flags().Uint64Var(&accountMin, "source-min", 0, "Minimum validator index in HD path range (incl.)")
	cmd.Flags().Uint64Var(&accountMax, "source-max", 0, "Maximum validator index in HD path range (excl.)")

	cmd.Flags().StringVar(&assignmentsLoc, "assignments", "assignments.json", "Path of the current assignments to adjust")
	cmd.Flags().StringVar(&hostname, "hostname", "morty", "Unique name of the remote host to assign validators to")
	cmd.Flags().Uint64VarP(&count, "count", "n", 0, "Amount of validators to assign")
	cmd.Flags().BoolVar(&addCount, "add", false, "If the assignment should add to the existing assignment")
	cmd.Flags().StringVar(&walletName, "wallet-name", "unknown imported wallet", "Name of the wallet, to tag accounts with in the assignments file")

	return cmd
}

// Narrow pubkeys: we don't want 0xAb... to be different from ab...
func narrowedPubkey(pub string) string {
	return strings.TrimPrefix(strings.ToLower(pub), "0x")
}

func assignVals(ctx context.Context,
	wallet types.WalletAccountByNameProvider, walletName string,
	minAcc uint64, maxAcc uint64,
	output WalletOutput,
	assignmentsPath string, hostname string, n uint64, addAssignments bool) error {

	va, err := LoadAssignments(assignmentsPath)
	if err != nil {
		return err
	}

	err = func() error {
		var prevAssignedToHost []ValidatorAssignEntry
		var prevAssignedToOther []ValidatorAssignEntry
		assignedPubkeys := make(map[string]struct{})
		for _, a := range va.Assignments.CurrentAssignments {
			pub := narrowedPubkey(a.Pubkey)
			// Check that there are no duplicate pubkeys in the previous store
			_, exists := assignedPubkeys[pub]
			if exists {
				return errors.New("DANGER !!!: current assignments contain duplicate pubkey\n")
			}
			assignedPubkeys[pub] = struct{}{}
			if a.Host == hostname {
				prevAssignedToHost = append(prevAssignedToHost, a)
			} else {
				prevAssignedToOther = append(prevAssignedToOther, a)
			}
		}

		prevAssignedToHostCount := uint64(len(prevAssignedToHost))

		var newAssignedToHost []ValidatorAssignEntry

		var toAssign uint64
		if addAssignments {
			newAssignedToHost = prevAssignedToHost
			toAssign = n
		} else {
			if n < prevAssignedToHostCount {
				// remove assignment
				va.Assignments.HistoricalAssignments = append(va.Assignments.HistoricalAssignments, prevAssignedToHost[n:]...)
				newAssignedToHost = prevAssignedToHost[:n]
				toAssign = 0
			} else {
				newAssignedToHost = prevAssignedToHost
				toAssign = n - prevAssignedToHostCount
			}
		}

		fmt.Printf("keeping %d/%d previous assignments to host (excl %d for others), and adding %d for total of %d assigned to \"%s\"\n",
			len(newAssignedToHost), prevAssignedToHostCount, len(prevAssignedToOther), toAssign, prevAssignedToHostCount+toAssign, hostname)

		assignmentTime := fmt.Sprintf("%d", time.Now().Unix())

		accountCount := 0
		if toAssign > 0 {
			// Try look for unassigned accounts in the wallet
			for i := minAcc; i < maxAcc; i++ {
				name := validatorKeyName(i)
				a, err := wallet.AccountByName(ctx, name)
				if err != nil {
					fmt.Printf("Account %s cannot be opened, continuing to next account.\n", name)
					continue
				}
				accountCount += 1
				pubkey := narrowedPubkey(hex.EncodeToString(a.PublicKey().Marshal()))
				// Add the account if it is not already assigned
				if _, ok := assignedPubkeys[pubkey]; !ok {
					fmt.Printf("Assigning account %s with pub %s\n", a.Name(), pubkey)
					assignedPubkeys[pubkey] = struct{}{}

					newAssignedToHost = append(newAssignedToHost, ValidatorAssignEntry{
						Pubkey:     pubkey,
						Host:       hostname,
						Time:       assignmentTime,
						Path:       name,
						WalletName: walletName,
					})
					toAssign -= 1
				}
				if toAssign == 0 {
					break
				}
			}
		}

		fmt.Printf("Read %d accounts from wallet to find as many unassigned accounts as needed. Can assign %d to host\n", accountCount, len(newAssignedToHost))

		// keep previous assignments to other hosts, along with new set of assignments for new host
		va.Assignments.CurrentAssignments = append(prevAssignedToOther, newAssignedToHost...)

		// sort by host, then pubkey
		sort.Slice(va.Assignments.CurrentAssignments, func(i, j int) bool {
			a := va.Assignments.CurrentAssignments[i]
			b := va.Assignments.CurrentAssignments[j]
			hostCmp := strings.Compare(a.Host, b.Host)
			if hostCmp == 0 {
				return strings.Compare(a.Pubkey, b.Pubkey) < 0
			}
			return hostCmp < 0
		})

		// Write new key store for current assignments to host
		for _, entry := range newAssignedToHost {
			a, err := wallet.AccountByName(ctx, entry.Path)
			if err != nil {
				return fmt.Errorf("cannot find wallet account for assignment, path: %s, pub: %s", entry.Path, entry.Pubkey)
			}
			if aLocked, ok := a.(types.AccountLocker); ok {
				if err := aLocked.Unlock(ctx, []byte{}); err != nil {
					return fmt.Errorf("failed to unlock priv key for account %s with pubkey %s: %v", a.ID().String(), entry.Pubkey, err)
				}
			}
			aPriv, ok := a.(types.AccountPrivateKeyProvider)
			if !ok {
				return fmt.Errorf("cannot get priv key for account %s with pubkey %s", a.ID().String(), entry.Pubkey)
			}
			priv, err := aPriv.PrivateKey(ctx)
			if err != nil {
				return fmt.Errorf("cannot read priv key for account %s with pubkey %s: %v", a.ID().String(), entry.Pubkey, err)
			}
			// account names must be prefixed with wallet name
			if err := output.InsertAccount(priv); err != nil {
				if err.Error() == fmt.Sprintf("account with name \"%s\" already exists", entry.Pubkey) {
					fmt.Printf("Account with pubkey %s already exists in output wallet, skipping it\n", entry.Pubkey)
				} else {
					return fmt.Errorf("failed to import account %s with pubkey %s into output wallet: %v", a.ID().String(), entry.Pubkey, err)
				}
			}
		}
		return nil
	}()

	if err != nil {
		// just unlock, but no writes
		_ = va.Unlock()
		return err
	}

	if err := va.Write(); err != nil {
		// Keep it locked, something went wrong during write. Can be dangerous for concurrent use, have the user look at it.
		return fmt.Errorf("failed to write assignments file! Keeping file lock! %v", err)
	}

	// Success, new assignments written and ready for use
	return va.Unlock()
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
				if asJsonList && i + 1 < accountMax {
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
	rootCmd.AddCommand(assignCommand())
	rootCmd.AddCommand(createMnemonicCmd())
	rootCmd.AddCommand(createDepositDatasCmd())
	rootCmd.AddCommand(createPubkeysCmd())
	rootCmd.SetOut(os.Stdout)
	rootCmd.SetErr(os.Stderr)
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
