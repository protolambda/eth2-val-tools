package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	filelock "github.com/MichaelS11/go-file-lock"
	"github.com/google/uuid"
	hbls "github.com/herumi/bls-eth-go-binary/bls"
	"github.com/spf13/cobra"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	e2wallet "github.com/wealdtech/go-eth2-wallet"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	filesystem "github.com/wealdtech/go-eth2-wallet-store-filesystem"
	types "github.com/wealdtech/go-eth2-wallet-types/v2"
	"io"
	"io/ioutil"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

func init() {
	hbls.Init(hbls.BLS12_381)
	hbls.SetETHmode(1)
}

type AccountID struct {
	uuid.UUID
}

func (id *AccountID) MarshalJSON() ([]byte, error) {
	var s = id.UUID.String()
	return json.Marshal(&s)
}

func (id *AccountID) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	uid, err := uuid.Parse(s)
	if err != nil {
		return fmt.Errorf("could not parse UUID: %v", err)
	}
	*id = AccountID{uid}
	return nil
}

type ValidatorAssignEntry struct {
	// Pubkey of validator, must be unique across store for current assignments
	Pubkey string `json:"pubkey"`
	// Host is the current remote assignment of the validator
	Host string `json:"host"`
	// Time of assignment
	Time string `json:"assignment_time"`
	// ID as used in the wallet
	AccountID AccountID `json:"account_id"`
	// Account name used in the source wallet (excl. wallet name prefix)
	SourceAccountName string `json:"name"`
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
	data["crypto"], err = encryptor.Encrypt(ke.secretKey.Marshal(), []byte(ke.passphrase))
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
	ndStorePath := path.Join(outPath, "wallets")
	walletName := "Assigned"
	outWal, err := e2wallet.CreateWallet(walletName,
		e2wallet.WithStore(filesystem.New(filesystem.WithLocation(ndStorePath))),
		e2wallet.WithType("nd"))
	if err != nil {
		return err
	}
	// nd wallets always unlock
	_ = outWal.Unlock(nil)
	outWallet := outWal.(types.WalletAccountImporter)
	for _, e := range ww.entries {
		if _, err := outWallet.ImportAccount(e.name, e.secretKey.Marshal(), []byte(e.passphrase)); err != nil {
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

func (ww *WalletWriter) WriteMetaOutputs(filepath string, keyMngWalletLoc string) error {
	if _, err := os.Stat(filepath); !os.IsNotExist(err) {
		return errors.New("output for assignments already exists! Aborting")
	}
	if err := os.MkdirAll(filepath, os.ModePerm); err != nil {
		return err
	}
	// What lighthouse requires as file name
	keyfileName := "voting-keystore.json"
	keyfilesPath := path.Join(filepath, "keys")
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

	// For Teku: a list of pubkeys. Used to find the keys and secrets to start a client with.
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

type AccountPasswords map[string]string

func ReadAccountPasswordsFile(filePath string) (AccountPasswords, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}

	accountToPass := make(AccountPasswords)

	// Create a new reader.
	r := csv.NewReader(f)
	for {
		record, err := r.Read()
		// Stop at EOF.
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, err
		}
		if len(record) != 2 {
			return nil, fmt.Errorf("expected 2 fields, but got %d: %v", len(record), record)
		}
		accountToPass[record[0]] = record[1]
	}
	return accountToPass, nil
}

func assignCommand() *cobra.Command {

	var keyMngWalletLoc string

	var outputDataPath string

	var sourceWalletLoc string
	var sourceWalletName string
	var sourceWalletPass string

	var sourceKeysPassCsv string

	var assignmentsLoc string
	var hostname string
	var count uint64
	var addCount bool

	cmd := &cobra.Command{
		Use:   "assign",
		Short: "Assign `n` available validators to `hostname`. If --add is true, it will add `n` assigned validators, instead of filling up to `n` total assigned to the host",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			checkErr := func(err error) {
				if err != nil {
					cmd.PrintErr(err)
					os.Exit(1)
				}
			}

			accountPasswords, err := ReadAccountPasswordsFile(sourceKeysPassCsv)
			checkErr(err)

			wal, err := e2wallet.OpenWallet(sourceWalletName, e2wallet.WithStore(storeWithOptions(sourceWalletPass, sourceWalletLoc)))
			checkErr(err)

			ww := &WalletWriter{}
			checkErr(assignVals(wal, ww, accountPasswords, assignmentsLoc, hostname, count, addCount))
			checkErr(ww.WriteMetaOutputs(outputDataPath, keyMngWalletLoc))
		},
	}
	cmd.Flags().StringVar(&keyMngWalletLoc, "key-man-loc", "", "Location to write to the 'location' field in the keymanager_opts.json file (Prysm only)")

	cmd.Flags().StringVar(&outputDataPath, "out-loc", "assigned_data", "Path of the output data for the host, where wallets, keys, secrets dir, etc. are written")

	cmd.Flags().StringVar(&sourceWalletLoc, "source-wallet-loc", "", "Path of the source wallet, empty to use default")
	cmd.Flags().StringVar(&sourceWalletName, "source-wallet-name", "Validators", "Name of the wallet to look for keys in")
	cmd.Flags().StringVar(&sourceWalletPass, "source-wallet-pass", "", "Pass for the source wallet itself. Empty to disable")

	cmd.Flags().StringVar(&sourceKeysPassCsv, "source-keys-csv", "", "CSV of source key passwords. Account name (with wallet prefix), account password")

	cmd.Flags().StringVar(&assignmentsLoc, "assignments", "assignments.json", "Path of the current assignments to adjust")
	cmd.Flags().StringVar(&hostname, "hostname", "morty", "Unique name of the remote host to assign validators to")
	cmd.Flags().Uint64VarP(&count, "count", "n", 0, "Amount of validators to assign")
	cmd.Flags().BoolVar(&addCount, "add", false, "If the assignment should add to the existing assignment")

	return cmd
}

// Narrow pubkeys: we don't want 0xAb... to be different from ab...
func narrowedPubkey(pub string) string {
	return strings.TrimPrefix(strings.ToLower(pub), "0x")
}

func assignVals(wallet types.Wallet, output WalletOutput,
	accountPasswords AccountPasswords, assignmentsPath string, hostname string, n uint64, addAssignments bool) error {

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
			for a := range wallet.Accounts() {
				accountCount += 1
				name := a.Name()
				_, ok := accountPasswords[fmt.Sprintf("%s/%s", wallet.Name(), name)]
				if !ok {
					fmt.Printf("Password for account %s is not known, looking for another account to assign.\n", name)
					continue
				}
				pubkey := narrowedPubkey(hex.EncodeToString(a.PublicKey().Marshal()))
				// Add the account if it is not already assigned
				if _, ok := assignedPubkeys[pubkey]; !ok {
					fmt.Printf("Assigning account %s with pub %s\n", a.Name(), pubkey)
					assignedPubkeys[pubkey] = struct{}{}

					newAssignedToHost = append(newAssignedToHost, ValidatorAssignEntry{
						Pubkey:            pubkey,
						Host:              hostname,
						Time:              assignmentTime,
						AccountID:         AccountID{a.ID()},
						SourceAccountName: name,
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
			password, ok := accountPasswords[fmt.Sprintf("%s/%s", wallet.Name(), entry.SourceAccountName)]
			if !ok {
				fmt.Printf("Password for assigned account %s is not known. Skipping, assigned but not including its key.\n", entry.SourceAccountName)
				continue
			}
			a, err := wallet.AccountByID(entry.AccountID.UUID)
			if err != nil {
				return fmt.Errorf("cannot find wallet account for assignment, id: %s, pub: %s", entry.AccountID.UUID.String(), entry.Pubkey)
			}
			if err := a.Unlock([]byte(password)); err != nil {
				return fmt.Errorf("failed to unlock priv key for account %s with pubkey %s: %v", a.ID().String(), entry.Pubkey, err)
			}
			aPriv, ok := a.(types.AccountPrivateKeyProvider)
			if !ok {
				return fmt.Errorf("cannot get priv key for account %s with pubkey %s", a.ID().String(), entry.Pubkey)
			}
			priv, err := aPriv.PrivateKey()
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

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
