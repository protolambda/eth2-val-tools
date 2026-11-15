package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

func runDepositData(t *testing.T, args ...string) (stdout string, stderr string) {
	t.Helper()
	cmd := createDepositDatasCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(append([]string{
		"--validators-mnemonic=" + testMnemonic,
		"--source-min=0",
		"--source-max=2",
		"--fork-version=0x00000000",
	}, args...))
	if err := cmd.Execute(); err != nil {
		t.Fatalf("deposit-data failed: %v (stderr: %s)", err, errOut.String())
	}
	return out.String(), errOut.String()
}

// assertCredentialPrefix checks that stdout holds only deposit data JSON lines, each with the given
// withdrawal credentials prefix, so warnings never leak into the machine-readable output.
func assertCredentialPrefix(t *testing.T, stdout string, prefix string) {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 deposit data lines, got %d: %q", len(lines), stdout)
	}
	for _, line := range lines {
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(line), &data); err != nil {
			t.Fatalf("stdout line is not deposit data JSON: %q: %v", line, err)
		}
		creds, _ := data["withdrawal_credentials"].(string)
		if !strings.HasPrefix(creds, prefix) {
			t.Fatalf("expected withdrawal credentials with prefix %s, got %q", prefix, creds)
		}
	}
}

func TestBlsWithdrawalCredsWarning(t *testing.T) {
	for _, credType := range []string{"0x01", "0x02", "0xb0"} {
		if got := blsWithdrawalCredsWarning(credType); got != "" {
			t.Errorf("expected no warning for %s, got %q", credType, got)
		}
	}
	got := blsWithdrawalCredsWarning("0x00")
	if !strings.Contains(got, "deprecated") || !strings.Contains(got, "--withdrawal-address") {
		t.Errorf("warning should say 0x00 is deprecated and point to --withdrawal-address, got %q", got)
	}
}

func TestResolveWithdrawalCredType(t *testing.T) {
	const addr = "0x742d35Cc6634C0532925a3b8D73e684B8F8832B2"
	cases := []struct {
		name      string
		credType  string
		addr      string
		mnemonic  string
		want      string
		errSubstr string
	}{
		{name: "explicit type kept", credType: "0x02", addr: addr, want: "0x02"},
		{name: "explicit 0x00 kept", credType: "0x00", mnemonic: testMnemonic, want: "0x00"},
		{name: "explicit type with both inputs", credType: "0x01", addr: addr, mnemonic: testMnemonic, want: "0x01"},
		{name: "address alone selects 0x01", addr: addr, want: "0x01"},
		{name: "mnemonic alone no longer selects 0x00", mnemonic: testMnemonic, errSubstr: "no longer defaults to 0x00"},
		{name: "both inputs are ambiguous", addr: addr, mnemonic: testMnemonic, errSubstr: "pass --withdrawal-credentials-type"},
		{name: "nothing given", errSubstr: "pass --withdrawal-address"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := resolveWithdrawalCredType(c.credType, c.addr, c.mnemonic)
			if c.errSubstr != "" {
				if err == nil || !strings.Contains(err.Error(), c.errSubstr) {
					t.Fatalf("expected error containing %q, got %q, %v", c.errSubstr, got, err)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("expected %q, got %q, %v", c.want, got, err)
			}
		})
	}
}

func TestDepositDataExplicitBlsCredentialsWarns(t *testing.T) {
	stdout, stderr := runDepositData(t,
		"--withdrawals-mnemonic="+testMnemonic,
		"--withdrawal-credentials-type=0x00",
	)
	assertCredentialPrefix(t, stdout, "00")
	if !strings.Contains(stderr, "WARNING: BLS (0x00) withdrawal credentials are deprecated") {
		t.Fatalf("expected deprecation warning on stderr, got %q", stderr)
	}
}

func TestDepositDataAddressWithoutTypeDefaultsTo0x01(t *testing.T) {
	stdout, stderr := runDepositData(t, "--withdrawal-address=0x742d35Cc6634C0532925a3b8D73e684B8F8832B2")
	assertCredentialPrefix(t, stdout, "01")
	if stderr != "" {
		t.Fatalf("expected no warning, got %q", stderr)
	}
}

func TestDepositDataExecutionAddressCredentialsDoNotWarn(t *testing.T) {
	for _, credType := range []string{"0x01", "0x02"} {
		t.Run(credType, func(t *testing.T) {
			stdout, stderr := runDepositData(t,
				"--withdrawal-address=0x742d35Cc6634C0532925a3b8D73e684B8F8832B2",
				"--withdrawal-credentials-type="+credType,
			)
			assertCredentialPrefix(t, stdout, strings.TrimPrefix(credType, "0x"))
			if stderr != "" {
				t.Fatalf("expected no warning for %s, got %q", credType, stderr)
			}
		})
	}
}

func TestDepositDataHelpMarksBlsDeprecated(t *testing.T) {
	cmd := createDepositDatasCmd()
	mnemonicFlag := cmd.Flags().Lookup("withdrawals-mnemonic")
	if mnemonicFlag == nil || !strings.HasPrefix(mnemonicFlag.Usage, "DEPRECATED") {
		t.Fatalf("--withdrawals-mnemonic usage should start with DEPRECATED, got %+v", mnemonicFlag)
	}
	if mnemonicFlag.Hidden {
		t.Fatalf("--withdrawals-mnemonic should stay visible in help while 0x00 is supported")
	}
	typeFlag := cmd.Flags().Lookup("withdrawal-credentials-type")
	if typeFlag.DefValue != "" {
		t.Fatalf("--withdrawal-credentials-type should have no default, got %q", typeFlag.DefValue)
	}
	if !strings.Contains(typeFlag.Usage, "0x00 (BLS, deprecated") || !strings.Contains(typeFlag.Usage, "recommended") {
		t.Fatalf("--withdrawal-credentials-type usage should mark 0x00 deprecated and 0x01 recommended, got %q", typeFlag.Usage)
	}
}
