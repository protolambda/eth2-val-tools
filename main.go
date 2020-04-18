package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	hbls "github.com/herumi/bls-eth-go-binary/bls"
	"github.com/juju/fslock"
	"github.com/spf13/cobra"
	e2wallet "github.com/wealdtech/go-eth2-wallet"
	filesystem "github.com/wealdtech/go-eth2-wallet-store-filesystem"
	types "github.com/wealdtech/go-eth2-wallet-types/v2"
	"io/ioutil"
	"os"
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
}

type ValidatorAssignments struct {
	// Historical assignments. Never forget where a key was hosted, unless manually removed.
	// Important for troubleshooting and debugging
	HistoricalAssignments []ValidatorAssignEntry `json:"historical_assignments"`
	// CurrentAssignments is an array instead of a map, to avoid random sorting
	CurrentAssignments []ValidatorAssignEntry `json:"current_assignments"`
}

func (vas *ValidatorAssignments) FindCurrentAssignments(hostname string) (out []ValidatorAssignEntry) {
	for _, a := range vas.CurrentAssignments {
		if a.Host == hostname {
			out = append(out, a)
		}
	}
	return out
}

type AssignmentsView struct {
	Assignments *ValidatorAssignments
	filepath    string
	lock        *fslock.Lock
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
	lock := fslock.New(filepath + ".lock")
	lockErr := lock.Lock()
	if lockErr != nil {
		return nil, fmt.Errorf("failed to acquire lock: %v", lockErr)
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
	}
	return &AssignmentsView{
		Assignments: &obj,
		filepath:    filepath,
		lock:        lock,
	}, nil
}

type Keypair struct {
	Name    string `json:"name"`
	PrivKey string `json:"priv"`
}

type RawWallet struct {
	Pairs []Keypair
	Path string
}

func (r *RawWallet) ImportAccount(name string, key []byte, passphrase []byte) (types.Account, error) {
	if len(passphrase) != 0 {
		return nil, errors.New("raw wallet type does not support passphrases")
	}
	r.Pairs = append(r.Pairs, Keypair{
		Name:    name,
		PrivKey: hex.EncodeToString(key),
	})
	// Write the key file again, not efficient, but fine for debugging purposes
	return nil, r.Write()
}

func (r *RawWallet) Write() error {
	if r.Path == "" {
		return errors.New("no path specified")
	}
	data, err := json.Marshal(r.Pairs)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(r.Path, data, 0644)
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

func assignCommand() *cobra.Command {

	var outputWalletType string
	var outputWalletLoc string
	var outputWalletName string
	var outWalletPass string
	var outKeyPass string

	var sourceWalletLoc string
	var sourceWalletName string
	var sourceWalletPass string
	var sourceKeyPass string

	var assignmentsLoc string
	var hostname string
	var count uint64
	var addCount bool

	cmd := &cobra.Command{
		Use:   "assign",
		Short: "Assign `n` available validators to `hostname`. If --add is true, it will add `n` assigned validators, instead of filling up to `n` total assigned to the host",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			wal, err := e2wallet.OpenWallet(sourceWalletName, e2wallet.WithStore(storeWithOptions(sourceWalletPass, sourceWalletLoc)))
			if err != nil {
				cmd.PrintErr(err)
				return
			}
			var outWallet types.WalletAccountImporter

			if outputWalletType == "raw" {
				outWallet = &RawWallet{Path: outputWalletLoc}
			} else if outputWalletType == "ethdo" {
				outWal, err := e2wallet.OpenWallet(outputWalletName, e2wallet.WithStore(storeWithOptions(outWalletPass, outputWalletLoc)))
				if err != nil {
					// Create wallet if it does not exist yet
					if err.Error() == "wallet not found" {
						store := storeWithOptions(outWalletPass, outputWalletLoc)
						outWal, err = e2wallet.CreateWallet(outputWalletName, e2wallet.WithStore(store))
						if err != nil {
							cmd.PrintErr(err)
							return
						}
					} else {
						cmd.PrintErr(err)
						return
					}
				}
				if err := outWal.Unlock([]byte(outWalletPass)); err != nil {
					cmd.PrintErr(err)
					return
				}
				var ok bool
				outWallet, ok = outWal.(types.WalletAccountImporter)
				if !ok {
					cmd.PrintErr("output wallet cannot import keys")
					return
				}
			}

			if err := assignVals(wal, outWallet, []byte(sourceKeyPass), []byte(outKeyPass), assignmentsLoc, hostname, count, addCount); err != nil {
				cmd.PrintErr(err)
				return
			}
		},
	}

	cmd.Flags().StringVar(&outputWalletType, "out-wallet-type", "ethdo", "Type of the output wallet")
	cmd.Flags().StringVar(&outputWalletLoc, "host-wallet-loc", "assigned_wallet", "Path of the output wallet for the host, where a keystore of assigned keys is written")
	cmd.Flags().StringVar(&outputWalletName, "host-wallet-name", "Assigned", "Name of the wallet, applicable if e.g. an ethdo wallet type.")
	cmd.Flags().StringVar(&outWalletPass, "host-wallet-pass", "", "Pass for the output wallet itself. Empty to disable")
	cmd.Flags().StringVar(&outKeyPass, "host-keys-pass", "", "Pass for the keys in the output wallet. Empty to disable")

	cmd.Flags().StringVar(&sourceWalletLoc, "source-wallet-loc", "", "Path of the source wallet, empty to use default")
	cmd.Flags().StringVar(&sourceWalletName, "source-wallet-name", "Validators", "Name of the wallet to look for keys in")
	cmd.Flags().StringVar(&sourceWalletPass, "source-wallet-pass", "", "Pass for the keys in the source wallet. Empty to disable")
	cmd.Flags().StringVar(&sourceKeyPass, "source-keys-pass", "", "Pass for the source wallet itself. Empty to disable")

	cmd.Flags().StringVar(&assignmentsLoc, "assignments", "assignments.json", "Path of the current assignments to adjust")
	cmd.Flags().StringVar(&hostname, "hostname", "morty", "Unique name of the remote host to assign validators to")
	cmd.Flags().Uint64VarP(&count, "count", "n", 0, "Amount of validators to assign")
	cmd.Flags().BoolVar(&addCount, "add", false, "If the assignment should add to the existing assignment")

	return cmd
}

func assignVals(wallet types.Wallet, outputWallet types.WalletAccountImporter, sourceKeyPass []byte, outKeyPass []byte, assignmentsPath string, hostname string, n uint64, addAssignments bool) error {
	va, err := LoadAssignments(assignmentsPath)
	if err != nil {
		return err
	}

	err = func() error {
		currentAssignments := va.Assignments.FindCurrentAssignments(hostname)

		var prevAssignedToHost []ValidatorAssignEntry
		var prevAssignedToOther []ValidatorAssignEntry
		assignedPubkeys := make(map[string]struct{})
		for _, a := range currentAssignments {
			// Check that there are no duplicate pubkeys in the previous store
			_, exists := assignedPubkeys[a.Pubkey]
			if exists {
				return errors.New("DANGER !!!: current assignments contain duplicate pubkey\n")
			}
			assignedPubkeys[a.Pubkey] = struct{}{}
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

		fmt.Printf("keeping %d/%d previous assignments, and adding %d for total of %d assigned to \"%s\"\n",
			len(newAssignedToHost), prevAssignedToHostCount, toAssign, prevAssignedToHostCount+toAssign, hostname)

		assignmentTime := fmt.Sprintf("%d", time.Now().Unix())

		accountCount := 0
		if toAssign > 0 {
			// Try look for unassigned accounts in the wallet
			for a := range wallet.Accounts() {
				accountCount += 1
				pubkey := strings.ToLower(hex.EncodeToString(a.PublicKey().Marshal()))
				// Add the account if it is not already assigned
				if _, ok := assignedPubkeys[pubkey]; !ok {
					fmt.Printf("Assigning account %s with pub %s\n", a.Name(), pubkey)
					assignedPubkeys[pubkey] = struct{}{}

					newAssignedToHost = append(newAssignedToHost, ValidatorAssignEntry{
						Pubkey:    pubkey,
						Host:      hostname,
						Time:      assignmentTime,
						AccountID: AccountID{a.ID()},
					})
					toAssign -= 1
				}
				if toAssign == 0 {
					break
				}
			}
		}

		fmt.Printf("Read %d accounts from wallet to find as many unassigned accounts as needed\n", accountCount)

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
			a, err := wallet.AccountByID(entry.AccountID.UUID)
			if err != nil {
				return fmt.Errorf("cannot find wallet account for assignment, id: %s, pub: %s", entry.AccountID.UUID.String(), entry.Pubkey)
			}
			aPriv, ok := a.(types.AccountPrivateKeyProvider)
			if !ok {
				return fmt.Errorf("cannot get priv key for account %s with pubkey %s", a.ID().String(), entry.Pubkey)
			}
			if err := a.Unlock(sourceKeyPass); err != nil {
				return fmt.Errorf("failed to unlock priv key for account %s with pubkey %s: %v", a.ID().String(), entry.Pubkey, err)
			}
			priv, err := aPriv.PrivateKey()
			if err != nil {
				return fmt.Errorf("cannot read priv key for account %s with pubkey %s: %v", a.ID().String(), entry.Pubkey, err)
			}
			if _, err := outputWallet.ImportAccount(entry.Pubkey, priv.Marshal(), outKeyPass); err != nil {
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

	rootCmd.Execute()
}
