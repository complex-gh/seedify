// Package main provides the seedify CLI tool for generating seed phrases from SSH keys.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/complex-gh/seedify"
	"github.com/mattn/go-isatty"
	"github.com/mattn/go-tty"
	mcobra "github.com/muesli/mango-cobra"
	"github.com/muesli/roff"
	"github.com/muesli/termenv"
	nostrpkg "github.com/nbd-wtf/go-nostr"
	"github.com/spf13/cobra"
	"github.com/tyler-smith/go-bip39"
	"github.com/tyler-smith/go-bip39/wordlists"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
	lang "golang.org/x/text/language"
	"golang.org/x/text/language/display"
)

const (
	maxWidth = 72
)

var (
	baseStyle  = lipgloss.NewStyle().Margin(0, 0, 1, 2) //nolint:mnd
	red        = lipgloss.Color(completeColor("#FF4444", "196", "9"))
	errorStyle = baseStyle.
			Foreground(red).
			Background(lipgloss.AdaptiveColor{Light: completeColor("#FFEBEB", "255", "7"), Dark: completeColor("#2B1A1A", "235", "8")}).
			Padding(1, 2) //nolint:mnd

	language        string
	wordCountStr    string
	seedPassphrase  string
	brave           bool
	full            bool
	nostr           bool
	bitcoin         bool
	ethereum        bool
	zcash           bool
	solana          bool
	tron            bool
	monero          bool
	zenprofile      bool
	publishRelays   string
	zenprofileAppID string

	rootCmd = &cobra.Command{
		Use:   "seedify <key-path>",
		Short: "Generate a seed phrase from an SSH key",
		Long: `Generate a seed phrase from an SSH key.

Valid word counts are: 12, 15, 16, 18, 21, or 24.
- 12, 15, 18, 21, 24 words use BIP39 format
- 16 words use Polyseed format

SECURITY TIP: Add a space before the command to prevent it from being
saved in your shell history. For example:
    seedify ~/.ssh/id_ed25519
    ^ (note the leading space)
Most shells (bash, zsh) are configured to ignore commands that start
with a space. Check your HISTCONTROL or HIST_IGNORE_SPACE settings.`,
		Example: `  seedify ~/.ssh/id_ed25519
  seedify ~/.ssh/id_ed25519 --words 12
  seedify ~/.ssh/id_ed25519 --words 12,24
  seedify ~/.ssh/id_ed25519 --words 12 --nostr
  seedify ~/.ssh/id_ed25519 --words 12,24 --nostr
  seedify ~/.ssh/id_ed25519 --nostr
  seedify ~/.ssh/id_ed25519 --words 12 --seed-passphrase "my-passphrase"
  seedify ~/.ssh/id_ed25519 --brave
  seedify ~/.ssh/id_ed25519 --full
  cat ~/.ssh/id_ed25519 | seedify --words 18`,
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// If no arguments provided and stdin is not a pipe, show help
			if len(args) == 0 {
				if fi, _ := os.Stdin.Stat(); (fi.Mode() & os.ModeNamedPipe) == 0 {
					return cmd.Help()
				}
			}

			if err := setLanguage(language); err != nil {
				return err
			}

			var keyPath string
			if len(args) > 0 {
				keyPath = args[0]
			}

			// --publish requires --zenprofile
			if publishRelays != "" && !zenprofile {
				return errors.New("--publish requires --zenprofile")
			}

			// Handle --brave flag: generate 25-word phrase with Brave Sync
			// This is a special case that bypasses the unified output
			if brave {
				mnemonic, err := generateBraveSyncPhrase(keyPath, seedPassphrase)
				if err != nil {
					if strings.Contains(err.Error(), "key is not password-protected") {
						return formatPasswordError(err)
					}
					return err
				}

				fmt.Println(mnemonic)
				return nil
			}

			// Handle --zenprofile flag: output public keys and addresses as DNS JSON
			// This is a special case that bypasses the unified output
			if zenprofile {
				record, nostrKeys, err := generateDNSRecord(keyPath, seedPassphrase)
				if err != nil {
					if strings.Contains(err.Error(), "key is not password-protected") {
						return formatPasswordError(err)
					}
					return err
				}

				if publishRelays != "" {
					relays := parseRelayURLs(publishRelays)
					if len(relays) > 0 {
						if err := publishDNSToRelays(record, nostrKeys, relays); err != nil {
							if strings.Contains(err.Error(), "key is not password-protected") {
								return formatPasswordError(err)
							}
							return err
						}
					}
				}

				jsonBytes, err := json.MarshalIndent(record, "", "  ")
				if err != nil {
					return fmt.Errorf("failed to marshal DNS JSON: %w", err)
				}
				fmt.Println(string(jsonBytes))
				return nil
			}

			// Default: print curated seed phrases; with btc/eth/nostr/sol/tron/xmr flags,
			// also show the relevant portions of the full output for those chains.
			// When --words is specified, output only the requested word counts (no derivations).
			if !full {
				hasDerivationFlags := bitcoin || ethereum || zcash || nostr || solana || tron || monero
				hasWordsFlag := wordCountStr != ""

				if hasWordsFlag {
					// --words specified: output only the requested seed phrases, no derivations
					parsedCounts, err := parseWordCounts(wordCountStr)
					if err != nil {
						return fmt.Errorf("invalid word counts: %w", err)
					}
					err = generateUnifiedOutput(keyPath, parsedCounts, seedPassphrase,
						false, false, false, false, false, false, false, false)
					if err != nil {
						if strings.Contains(err.Error(), "key is not password-protected") {
							return formatPasswordError(err)
						}
						return err
					}
				} else if hasDerivationFlags {
					err := generatePhrasesWithDerivations(keyPath, seedPassphrase,
						nostr, bitcoin, ethereum, zcash, solana, tron, monero)
					if err != nil {
						if strings.Contains(err.Error(), "key is not password-protected") {
							return formatPasswordError(err)
						}
						return err
					}
				} else {
					err := generatePhrasesOutput(keyPath, seedPassphrase)
					if err != nil {
						if strings.Contains(err.Error(), "key is not password-protected") {
							return formatPasswordError(err)
						}
						return err
					}
				}
				return nil
			}

			// --full: generate unified output (seed phrases + wallet derivations)
			hasWordsFlag := wordCountStr != ""
			hasNostrFlag := nostr
			hasCryptoFlags := bitcoin || ethereum || zcash || solana || tron || monero || zenprofile
			hasAnyDerivationFlags := hasWordsFlag || hasNostrFlag || hasCryptoFlags

			var wordCounts []int
			var deriveNostr bool
			var showBrave bool
			var deriveBtc, deriveEth, deriveZec, deriveSol, deriveTron, deriveXmr bool

			if !hasAnyDerivationFlags {
				wordCounts = []int{12, 15, 16, 18, 21, 24}
				deriveNostr = true
				showBrave = true
				deriveBtc = true
				deriveEth = true
				deriveZec = true
				deriveSol = true
				deriveTron = true
				deriveXmr = true
			} else {
				if hasWordsFlag {
					parsedCounts, err := parseWordCounts(wordCountStr)
					if err != nil {
						return fmt.Errorf("invalid word counts: %w", err)
					}
					wordCounts = parsedCounts
				} else if hasCryptoFlags {
					wordCounts = []int{}
					if bitcoin {
						wordCounts = append(wordCounts, 12) //nolint:mnd
					}
					if monero {
						wordCounts = append(wordCounts, 16) //nolint:mnd
					}
					if bitcoin || ethereum || zcash || solana || tron {
						wordCounts = append(wordCounts, 24) //nolint:mnd
					}
				}
				deriveNostr = hasNostrFlag
				showBrave = false
				deriveBtc = bitcoin
				deriveEth = ethereum
				deriveZec = zcash
				deriveSol = solana
				deriveTron = tron
				deriveXmr = monero
			}

			err := generateUnifiedOutput(keyPath, wordCounts, seedPassphrase, deriveNostr, showBrave, deriveBtc, deriveEth, deriveZec, deriveSol, deriveTron, deriveXmr)
			if err != nil && strings.Contains(err.Error(), "key is not password-protected") {
				return formatPasswordError(err)
			}
			return err
		},
	}

	manCmd = &cobra.Command{
		Use:          "man",
		Args:         cobra.NoArgs,
		Short:        "generate man pages",
		Hidden:       true,
		SilenceUsage: true,
		RunE: func(*cobra.Command, []string) error {
			manPage, err := mcobra.NewManPage(1, rootCmd)
			if err != nil {
				//nolint: wrapcheck
				return err
			}
			manPage = manPage.WithSection("Copyright", "(C) 2022 Charmbracelet, Inc.\n"+
				"Released under MIT license.")
			fmt.Println(manPage.Build(roff.NewDocument()))
			return nil
		},
	}

	braveSync25thCmd = &cobra.Command{
		Use:   "brave-sync-25th",
		Short: "Get the 25th word for Brave Sync (changes daily)",
		Long: `Get the 25th word for Brave Sync based on the current date.

The 25th word changes daily and is calculated from the epoch date
"Tue, 10 May 2022 00:00:00 GMT". The number of days since the epoch
is used as an index into the BIP39 English word list.

This replicates the logic from:
https://alexeybarabash.github.io/25th-brave-sync-word/

Warning: Brave does not officially support using the Sync code as a backup
and you should not rely on this continuing to work in the future. Use the
export functionality in bookmarks and the password manager instead.`,
		Example: `  seedify brave-sync-25th
  seedify brave-sync-25th --date "2024-01-15"`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			var word string
			var err error

			// Check if a specific date was provided
			if dateStr != "" {
				date, parseErr := time.Parse("2006-01-02", dateStr)
				if parseErr != nil {
					return fmt.Errorf("could not parse date %q: use format YYYY-MM-DD: %w", dateStr, parseErr)
				}
				word, err = seedify.BraveSync25thWordForDate(date)
			} else {
				word, err = seedify.BraveSync25thWord()
			}

			if err != nil {
				return fmt.Errorf("could not get 25th word: %w", err)
			}

			fmt.Println(word)
			return nil
		},
	}

	dateStr string

	// completionCmd generates shell completion scripts for bash, zsh, fish, and powershell.
	completionCmd = &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion script",
		Long: `Generate shell completion script for seedify.

To load completions:

Bash:
  $ source <(seedify completion bash)

  # To load completions for each session, execute once:
  # Linux:
  $ seedify completion bash > /etc/bash_completion.d/seedify
  # macOS:
  $ seedify completion bash > $(brew --prefix)/etc/bash_completion.d/seedify

Zsh:
  # If shell completion is not already enabled in your environment,
  # you will need to enable it. You can execute the following once:
  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  # To load completions for each session, execute once:
  $ seedify completion zsh > "${fpath[1]}/_seedify"

  # You will need to start a new shell for this setup to take effect.

Fish:
  $ seedify completion fish | source

  # To load completions for each session, execute once:
  $ seedify completion fish > ~/.config/fish/completions/seedify.fish

PowerShell:
  PS> seedify completion powershell | Out-String | Invoke-Expression

  # To load completions for every new session, run:
  PS> seedify completion powershell > seedify.ps1
  # and source this file from your PowerShell profile.
`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		SilenceUsage:          true,
		RunE: func(_ *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return rootCmd.GenBashCompletion(os.Stdout)
			case "zsh":
				return rootCmd.GenZshCompletion(os.Stdout)
			case "fish":
				return rootCmd.GenFishCompletion(os.Stdout, true)
			case "powershell":
				return rootCmd.GenPowerShellCompletionWithDesc(os.Stdout)
			default:
				return fmt.Errorf("unknown shell: %s", args[0])
			}
		},
	}
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&language, "language", "l", "en", "Language")
	rootCmd.PersistentFlags().StringVarP(&wordCountStr, "words", "w", "", "Word counts to generate (comma-separated: 12,15,18,21,24)")
	rootCmd.PersistentFlags().StringVar(&seedPassphrase, "seed-passphrase", "", "Passphrase to combine with SSH key seed for additional entropy")
	rootCmd.PersistentFlags().BoolVar(&brave, "brave", false, "Generate 25-word phrase with Brave Sync")
	rootCmd.PersistentFlags().BoolVar(&full, "full", false, "Print full output (all word counts, Nostr keys, crypto derivations)")
	rootCmd.PersistentFlags().BoolVar(&nostr, "nostr", false, "Derive Nostr keys (npub/nsec) from seed phrase.")
	rootCmd.PersistentFlags().BoolVar(&bitcoin, "btc", false, "Derive Bitcoin address from 24-word seed phrase")
	rootCmd.PersistentFlags().BoolVar(&ethereum, "eth", false, "Derive Ethereum address from 24-word seed phrase")
	rootCmd.PersistentFlags().BoolVar(&zcash, "zec", false, "Derive Zcash address from 24-word seed phrase")
	rootCmd.PersistentFlags().BoolVar(&solana, "sol", false, "Derive Solana address from 24-word seed phrase")
	rootCmd.PersistentFlags().BoolVar(&tron, "tron", false, "Derive Tron address from 24-word seed phrase")
	rootCmd.PersistentFlags().BoolVar(&monero, "xmr", false, "Derive Monero address from 16-word polyseed")
	rootCmd.PersistentFlags().BoolVar(&zenprofile, "zenprofile", false, "Output public keys and addresses as DNS JSON to stdout")
	rootCmd.PersistentFlags().StringVar(&publishRelays, "publish", "", "When used with --zenprofile: publish NIP-78 Kind 30078 event to these relays (comma-separated, e.g. relay.primal.net,relay.damus.io)")
	rootCmd.PersistentFlags().StringVar(&zenprofileAppID, "zenprofile-app-id", "app.zenprofile.contactme", "When used with --zenprofile --publish: NIP-78 d tag value for the event identifier")
	rootCmd.AddCommand(manCmd)
	rootCmd.AddCommand(braveSync25thCmd)
	rootCmd.AddCommand(completionCmd)
	braveSync25thCmd.Flags().StringVar(&dateStr, "date", "", "Get the 25th word for a specific date (format: YYYY-MM-DD)")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// getDefaultSSHDir returns the default SSH directory for the current platform.
// On Unix-like systems (Linux, macOS), this is ~/.ssh/.
// On Windows, this is %USERPROFILE%\.ssh\.
func getDefaultSSHDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not get home directory: %w", err)
	}
	return filepath.Join(homeDir, ".ssh"), nil
}

// getSSHKeygenCommand returns the appropriate ssh-keygen command name for the platform.
// On Windows, this is "ssh-keygen.exe", on other platforms it's "ssh-keygen".
func getSSHKeygenCommand() string {
	if runtime.GOOS == "windows" {
		return "ssh-keygen.exe"
	}
	return "ssh-keygen"
}

// generateKeyWithSSHKeygen uses ssh-keygen to generate a new ed25519 key at the specified path.
// It runs "ssh-keygen -t ed25519 -f <path>" interactively so the user can set a passphrase.
// Returns an error if the key generation fails.
func generateKeyWithSSHKeygen(keyPath string) error {
	cmdName := getSSHKeygenCommand()
	// Run interactively without -N flag so user can set a passphrase
	// Without -q flag so user can see prompts and confirmations
	// Using context.Background() since this is an interactive command with no timeout
	// G204: cmdName is controlled (only "ssh-keygen" or "ssh-keygen.exe")
	cmd := exec.CommandContext(context.Background(), cmdName, "-t", "ed25519", "-f", keyPath) //nolint:gosec
	// Connect stdin, stdout, and stderr to allow full interaction
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to generate key with %s: %w", cmdName, err)
	}
	return nil
}

// resolveKeyPath attempts to resolve a key path. If the path doesn't exist
// and appears to be just a filename (no directory separators), it will check
// the default SSH directory for a key with that name.
func resolveKeyPath(path string) (string, error) {
	// If path is "-", use it as-is
	if path == "-" {
		return path, nil
	}

	// Check if the path exists as-is
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}

	// Check if path is just a filename (no directory separators)
	// Clean the path first to normalize it, then check if the directory
	// component is "." (current directory) or empty
	cleanedPath := filepath.Clean(path)
	dir := filepath.Dir(cleanedPath)

	// If the directory is not "." or empty, it's a path with directory components
	// - don't check default SSH directory
	if dir != "." && dir != "" {
		return "", fmt.Errorf("could not open %s: %w", path, os.ErrNotExist)
	}

	// Also check if the original path explicitly starts with relative path indicators
	// These are relative paths that should not be checked in default SSH directory
	// Check for both Unix-style (./, ../) and Windows-style (.\, ..\) prefixes
	pathLower := strings.ToLower(path)
	if strings.HasPrefix(pathLower, "./") || strings.HasPrefix(pathLower, "../") ||
		strings.HasPrefix(pathLower, ".\\") || strings.HasPrefix(pathLower, "..\\") {
		return "", fmt.Errorf("could not open %s: %w", path, os.ErrNotExist)
	}

	// Path appears to be just a filename, try default SSH directory
	sshDir, err := getDefaultSSHDir()
	if err != nil {
		return "", fmt.Errorf("could not determine SSH directory: %w", err)
	}

	// Use the cleaned path (or original if it's just a filename) to construct the default path
	filename := filepath.Base(cleanedPath)
	defaultPath := filepath.Join(sshDir, filename)

	// Check if the file exists in the default SSH directory
	if _, err := os.Stat(defaultPath); err == nil {
		return defaultPath, nil
	}

	// As a last fallback, try using ssh-keygen to generate the key
	// This will create a new ed25519 key at the default SSH directory path
	if err := generateKeyWithSSHKeygen(defaultPath); err != nil {
		return "", fmt.Errorf("could not open %s: file not found in current directory or %s, and failed to generate key with %s: %w", path, sshDir, getSSHKeygenCommand(), err)
	}

	// Key was successfully generated, return the path
	return defaultPath, nil
}

func openFileOrStdin(path string) (*os.File, error) {
	if path == "-" {
		return os.Stdin, nil
	}

	if fi, _ := os.Stdin.Stat(); (fi.Mode() & os.ModeNamedPipe) != 0 {
		return os.Stdin, nil
	}

	// Resolve the key path (check default SSH directory if needed)
	resolvedPath, err := resolveKeyPath(path)
	if err != nil {
		return nil, err
	}

	// G304: resolvedPath is user-provided input, which is expected for a CLI tool
	f, err := os.Open(resolvedPath) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("could not open %s: %w", resolvedPath, err)
	}
	return f, nil
}

func parsePrivateKey(bts, pass []byte) (interface{}, error) {
	if len(pass) == 0 {
		//nolint: wrapcheck
		return ssh.ParseRawPrivateKey(bts)
	}
	//nolint: wrapcheck
	return ssh.ParseRawPrivateKeyWithPassphrase(bts, pass)
}

// generateBraveSyncPhrase generates a 25-word seed phrase with Brave Sync.
// seedPassphrase is combined with the SSH key seed to add additional entropy.
func generateBraveSyncPhrase(path string, seedPassphrase string) (string, error) {
	f, err := openFileOrStdin(path)
	if err != nil {
		return "", fmt.Errorf("could not read key: %w", err)
	}
	defer f.Close() //nolint:errcheck
	bts, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("could not read key: %w", err)
	}

	// Check if key is password-protected (required for this command)
	if isProtected, err := isKeyPasswordProtected(bts); err == nil && !isProtected {
		return "", fmt.Errorf("key is not password-protected: keys are required to be password-protected")
	}

	key, err := parsePrivateKey(bts, nil)
	if err != nil && isPasswordError(err) {
		// Key requires a password - ask for it and parse again with the same bytes
		pass, err := askKeyPassphrase(path)
		if err != nil {
			return "", err
		}
		// Parse again with the password using the bytes we already have
		key, err = parsePrivateKey(bts, pass)
		if err != nil {
			return "", fmt.Errorf("could not parse key with passphrase: %w", err)
		}
	} else if err != nil {
		return "", fmt.Errorf("could not parse key: %w", err)
	}

	switch key := key.(type) {
	case *ed25519.PrivateKey:
		// Generate 25-word mnemonic with Brave Sync
		mnemonic, err := seedify.ToMnemonicWithBraveSync(key, seedPassphrase)
		if err != nil {
			return "", fmt.Errorf("could not generate Brave Sync mnemonic: %w", err)
		}
		return mnemonic, nil
	default:
		return "", fmt.Errorf("unknown key type: %v", key)
	}
}

// printPEMPhrase prints a seed phrase wrapped in PEM-style BEGIN/END markers.
// The label is used in both the BEGIN and END lines (e.g., "12-WORD SEED PHRASE").
// Note: This function does not add extra spacing; callers are responsible for
// managing blank lines between outputs.
func printPEMPhrase(label string, phrase string) {
	fmt.Printf("-----BEGIN %s-----\n%s\n-----END %s-----\n", label, phrase, label)
}

// generatePhrasesOutput generates a curated set of seed phrases from the SSH key.
// It prints the following phrases in order:
//  1. 12-word BIP39 seed phrase
//  2. 16-word Polyseed seed phrase
//  3. 24-word BIP39 seed phrase
//  4. 24-word wallet seed phrase (wallet-prefixed)
//  5. 24-word vault seed phrase (vault-prefixed)
//  6. Brave 25-word seed phrase (24 brave-prefixed words + 25th word)
//
//nolint:funlen
func generatePhrasesOutput(keyPath string, seedPassphrase string) error {
	// Parse the key once
	f, err := openFileOrStdin(keyPath)
	if err != nil {
		return fmt.Errorf("could not read key: %w", err)
	}
	defer f.Close() //nolint:errcheck
	bts, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("could not read key: %w", err)
	}

	// Check if key is password-protected (required)
	isProtected, err := isKeyPasswordProtected(bts)
	if err == nil && !isProtected {
		return fmt.Errorf("key is not password-protected: keys are required to be password-protected")
	}

	key, err := parsePrivateKey(bts, nil)
	if err != nil && isPasswordError(err) {
		// Key requires a password - ask for it and parse again with the same bytes
		pass, passErr := askKeyPassphrase(keyPath)
		if passErr != nil {
			return passErr
		}
		key, err = parsePrivateKey(bts, pass)
		if err != nil {
			return fmt.Errorf("could not parse key with passphrase: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("could not parse key: %w", err)
	}

	ed25519Key, ok := key.(*ed25519.PrivateKey)
	if !ok {
		return fmt.Errorf("unknown key type: %v", key)
	}

	// 1. 12-word seed phrase
	mnemonic12, err := seedify.ToMnemonicWithLength(ed25519Key, 12, seedPassphrase, false) //nolint:mnd
	if err != nil {
		return fmt.Errorf("could not generate 12-word mnemonic: %w", err)
	}
	// 2 empty lines before the first output
	fmt.Print("\n\n")
	printPEMPhrase("12-WORD SEED PHRASE", mnemonic12)

	// 2. 16-word seed phrase (Polyseed)
	mnemonic16, err := seedify.ToMnemonicWithLength(ed25519Key, 16, seedPassphrase, false) //nolint:mnd
	if err != nil {
		return fmt.Errorf("could not generate 16-word mnemonic: %w", err)
	}
	// 2 empty lines between outputs
	fmt.Print("\n\n")
	printPEMPhrase("16-WORD POLYSEED", mnemonic16)

	// 3. 24-word seed phrase (standard, no prefix)
	mnemonic24, err := seedify.ToMnemonicWithLength(ed25519Key, 24, seedPassphrase, false) //nolint:mnd
	if err != nil {
		return fmt.Errorf("could not generate 24-word mnemonic: %w", err)
	}
	// 2 empty lines between outputs
	fmt.Print("\n\n")
	printPEMPhrase("24-WORD SEED PHRASE (charmbracelet/MELT)", mnemonic24)

	// 4. Brave 25-word seed phrase (24 brave-prefixed words + 25th word)
	braveMnemonic, err := seedify.ToMnemonicWithBraveSync(ed25519Key, seedPassphrase)
	if err != nil {
		return fmt.Errorf("could not generate brave 25-word mnemonic: %w", err)
	}
	// 2 empty lines between outputs
	fmt.Print("\n\n")
	printPEMPhrase("25-WORD BRAVE-SYNC", braveMnemonic)

	// 2 empty lines after the last output
	fmt.Print("\n\n")

	return nil
}

// generatePhrasesWithDerivations outputs the curated seed phrases followed by
// only the derivations requested by the flags (nostr, btc, eth, zec, sol, tron, xmr).
// Each flag shows the relevant portions of the full output for that chain.
//
//nolint:funlen
func generatePhrasesWithDerivations(keyPath string, seedPassphrase string, deriveNostr, deriveBtc, deriveEth, deriveZec, deriveSol, deriveTron, deriveXmr bool) error {
	f, err := openFileOrStdin(keyPath)
	if err != nil {
		return fmt.Errorf("could not read key: %w", err)
	}
	defer f.Close() //nolint:errcheck
	bts, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("could not read key: %w", err)
	}

	isProtected, err := isKeyPasswordProtected(bts)
	if err == nil && !isProtected {
		return fmt.Errorf("key is not password-protected: keys are required to be password-protected")
	}

	key, err := parsePrivateKey(bts, nil)
	if err != nil && isPasswordError(err) {
		pass, passErr := askKeyPassphrase(keyPath)
		if passErr != nil {
			return passErr
		}
		key, err = parsePrivateKey(bts, pass)
		if err != nil {
			return fmt.Errorf("could not parse key with passphrase: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("could not parse key: %w", err)
	}

	ed25519Key, ok := key.(*ed25519.PrivateKey)
	if !ok {
		return fmt.Errorf("unknown key type: %v", key)
	}

	// Generate mnemonics for phrases and derivations
	mnemonic12, err := seedify.ToMnemonicWithLength(ed25519Key, 12, seedPassphrase, false) //nolint:mnd
	if err != nil {
		return fmt.Errorf("could not generate 12-word mnemonic: %w", err)
	}
	mnemonic16, err := seedify.ToMnemonicWithLength(ed25519Key, 16, seedPassphrase, false) //nolint:mnd
	if err != nil {
		return fmt.Errorf("could not generate 16-word mnemonic: %w", err)
	}
	mnemonic24, err := seedify.ToMnemonicWithLength(ed25519Key, 24, seedPassphrase, false) //nolint:mnd
	if err != nil {
		return fmt.Errorf("could not generate 24-word mnemonic: %w", err)
	}
	braveMnemonic, err := seedify.ToMnemonicWithBraveSync(ed25519Key, seedPassphrase)
	if err != nil {
		return fmt.Errorf("could not generate brave 25-word mnemonic: %w", err)
	}

	// Output curated phrases in PEM format
	fmt.Print("\n\n")
	printPEMPhrase("12-WORD SEED PHRASE", mnemonic12)
	fmt.Print("\n\n")
	printPEMPhrase("16-WORD POLYSEED", mnemonic16)
	fmt.Print("\n\n")
	printPEMPhrase("24-WORD SEED PHRASE (charmbracelet/MELT)", mnemonic24)
	fmt.Print("\n\n")
	printPEMPhrase("25-WORD BRAVE-SYNC", braveMnemonic)
	fmt.Print("\n\n")

	// Output requested derivations only
	hasDerivations := deriveNostr || deriveBtc || deriveEth || deriveZec || deriveSol || deriveTron || deriveXmr
	if !hasDerivations {
		return nil
	}

	// Monero from 16-word polyseed
	if deriveXmr {
		xmrKeys, err := seedify.DeriveMoneroKeys(mnemonic16, 9) //nolint:mnd
		if err != nil {
			return fmt.Errorf("failed to derive Monero keys from 16-word polyseed: %w", err)
		}
		fmt.Printf("[monero addresses from 16 word polyseed]\n")
		fmt.Println()
		fmt.Printf("%s (primary address)\n", xmrKeys.PrimaryAddress)
		for i, subaddr := range xmrKeys.Subaddresses {
			fmt.Printf("> %s (subaddress 0,%d)\n", subaddr, i+1)
		}
		fmt.Println()
	}

	// Nostr keys from 12 and 24 word
	if deriveNostr {
		for _, m := range []struct {
			mnemonic string
			count    int
		}{
			{mnemonic12, 12},
			{mnemonic24, 24},
		} {
			nostrKeys, err := seedify.DeriveNostrKeysWithHex(m.mnemonic, "")
			if err != nil {
				return fmt.Errorf("failed to derive Nostr keys from %d-word mnemonic: %w", m.count, err)
			}
			fmt.Printf("[nostr keys from %d word seed]\n", m.count)
			fmt.Println()
			fmt.Printf("%s (nostr public key aka \"nostr user\")\n", nostrKeys.Npub)
			fmt.Printf("└─ %s (hex)\n", nostrKeys.PubKeyHex)
			fmt.Printf("%s (nostr secret key aka \"nostr pass\")\n", nostrKeys.Nsec)
			fmt.Printf("└─ %s (hex)\n", nostrKeys.PrivKeyHex)
			fmt.Println()
		}
	}

	// Bitcoin from 12 and 24 word
	if deriveBtc {
		if err := displayBitcoinOutput(mnemonic12, 12); err != nil { //nolint:mnd
			return err
		}
		if err := displayBitcoinOutput(mnemonic24, 24); err != nil { //nolint:mnd
			return err
		}
	}

	// Ethereum, Solana, Tron, and EVM chains from 24 word
	if deriveEth {
		ethAddr, err := seedify.DeriveEthereumAddress(mnemonic24, "")
		if err != nil {
			return fmt.Errorf("failed to derive Ethereum address from 24-word seed: %w", err)
		}
		fmt.Printf("[ethereum address from 24 word seed]\n")
		fmt.Println()
		fmt.Println(ethAddr)
		fmt.Println()

		for _, name := range []string{"arbitrum", "avalanche", "base", "bnbchain", "cronos", "optimism", "polygon"} {
			fmt.Printf("[%s address from 24 word seed]\n", name)
			fmt.Println()
			fmt.Println(ethAddr)
			fmt.Println()
		}
	}
	if deriveZec {
		zcashAddr, err := seedify.DeriveZcashAddress(mnemonic24, "")
		if err != nil {
			return fmt.Errorf("failed to derive Zcash address from 24-word seed: %w", err)
		}
		fmt.Printf("[zcash address from 24 word seed]\n")
		fmt.Println()
		fmt.Println(zcashAddr)
		fmt.Println()
	}
	if deriveSol {
		solAddr, err := seedify.DeriveSolanaAddress(mnemonic24, "")
		if err != nil {
			return fmt.Errorf("failed to derive Solana address from 24-word seed: %w", err)
		}
		fmt.Printf("[solana address from 24 word seed]\n")
		fmt.Println()
		fmt.Println(solAddr)
		fmt.Println()
	}
	if deriveTron {
		tronAddr, err := seedify.DeriveTronAddress(mnemonic24, "")
		if err != nil {
			return fmt.Errorf("failed to derive Tron address from 24-word seed: %w", err)
		}
		fmt.Printf("[tron address from 24 word seed]\n")
		fmt.Println()
		fmt.Println(tronAddr)
		fmt.Println()
	}

	return nil
}

func isPasswordError(err error) bool {
	var kerr *ssh.PassphraseMissingError
	return errors.As(err, &kerr)
}

// isKeyPasswordProtected checks if an SSH key requires a password.
// It attempts to parse the key without a password. If parsing succeeds,
// the key is not password-protected. If it fails with PassphraseMissingError,
// the key is password-protected.
func isKeyPasswordProtected(bts []byte) (bool, error) {
	_, err := parsePrivateKey(bts, nil)
	if err == nil {
		// Key parsed successfully without password - not password-protected
		return false, nil
	}
	if isPasswordError(err) {
		// Key requires a password - password-protected
		return true, nil
	}
	// Some other error occurred - we can't determine if it's password-protected
	// Return the error so the caller can handle it
	return false, fmt.Errorf("could not determine if key is password-protected: %w", err)
}

func getWidth(maxw int) int {
	w, _, err := term.GetSize(int(os.Stdout.Fd())) //nolint: gosec
	if err != nil || w > maxw {
		return maxWidth
	}
	return w
}

func renderBlock(w io.Writer, s lipgloss.Style, width int, str string) {
	_, _ = io.WriteString(w, s.Width(width).Render(str))
	_, _ = io.WriteString(w, "\n")
}

// formatPasswordError formats an error message with purple styling,
// similar to the success message format. It displays the styled error and returns
// a simple error so the command exits with a non-zero code.
func formatPasswordError(err error) error {
	if isatty.IsTerminal(os.Stdout.Fd()) {
		b := strings.Builder{}
		w := getWidth(maxWidth)

		b.WriteRune('\n')
		renderBlock(&b, errorStyle, w, err.Error())
		b.WriteRune('\n')

		fmt.Print(b.String())
	}
	// Return a simple error message (cobra may print this to stderr, but the styled
	// version has already been shown)
	return fmt.Errorf("keys are required to be password-protected")
}

func completeColor(truecolor, ansi256, ansi string) string {
	//nolint: exhaustive
	switch lipgloss.ColorProfile() {
	case termenv.TrueColor:
		return truecolor
	case termenv.ANSI256:
		return ansi256
	}
	return ansi
}

// setLanguage sets the language of the big39 mnemonic seed.
func setLanguage(language string) error {
	list := getWordlist(language)
	if list == nil {
		return fmt.Errorf("this language is not supported")
	}
	bip39.SetWordList(list)
	return nil
}

func sanitizeLang(s string) string {
	return strings.ReplaceAll(strings.ToLower(s), " ", "-")
}

var wordLists = map[lang.Tag][]string{
	lang.Chinese:              wordlists.ChineseSimplified,
	lang.SimplifiedChinese:    wordlists.ChineseSimplified,
	lang.TraditionalChinese:   wordlists.ChineseTraditional,
	lang.Czech:                wordlists.Czech,
	lang.AmericanEnglish:      wordlists.English,
	lang.BritishEnglish:       wordlists.English,
	lang.English:              wordlists.English,
	lang.French:               wordlists.French,
	lang.Italian:              wordlists.Italian,
	lang.Japanese:             wordlists.Japanese,
	lang.Korean:               wordlists.Korean,
	lang.Spanish:              wordlists.Spanish,
	lang.EuropeanSpanish:      wordlists.Spanish,
	lang.LatinAmericanSpanish: wordlists.Spanish,
}

func getWordlist(language string) []string {
	language = sanitizeLang(language)
	tag := lang.Make(language)
	en := display.English.Languages() // default language name matcher
	for t := range wordLists {
		if sanitizeLang(en.Name(t)) == language {
			tag = t
			break
		}
	}
	if tag == lang.Und { // Unknown language
		return nil
	}
	base, _ := tag.Base()
	btag := lang.MustParse(base.String())
	wl := wordLists[tag]
	if wl == nil {
		return wordLists[btag]
	}
	return wl
}

func readPassword(msg string) ([]byte, error) {
	_, _ = fmt.Fprint(os.Stderr, msg)
	t, err := tty.Open()
	if err != nil {
		return nil, fmt.Errorf("could not open tty: %w", err)
	}
	defer t.Close()                                     //nolint: errcheck
	pass, err := term.ReadPassword(int(t.Input().Fd())) //nolint: gosec
	if err != nil {
		return nil, fmt.Errorf("could not read passphrase: %w", err)
	}
	return pass, nil
}

// generateUnifiedOutput generates seed phrases and wallet derivations for the specified word counts.
// It displays outputs in a fixed order: seed phrase first, then wallet derivations.
// When deriveNostr is true, it derives Nostr keys directly from the SSH key (not from seed phrases).
// When showBrave is true, it also displays the brave 24-word seed phrase at the end.
// Crypto address flags (deriveBtc, deriveEth, deriveSol, deriveTron, deriveXmr) control which addresses to derive.
func generateUnifiedOutput(keyPath string, wordCounts []int, seedPassphrase string, deriveNostr bool, showBrave bool, deriveBtc, deriveEth, deriveZec, deriveSol, deriveTron, deriveXmr bool) error {
	// Parse the key once
	f, err := openFileOrStdin(keyPath)
	if err != nil {
		return fmt.Errorf("could not read key: %w", err)
	}
	defer f.Close() //nolint:errcheck
	bts, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("could not read key: %w", err)
	}

	// Check if key is password-protected (required for this command)
	// If we can't determine protection status (err != nil), continue with normal parsing flow
	isProtected, err := isKeyPasswordProtected(bts)
	if err == nil && !isProtected {
		// Key is not password-protected - reject it
		return fmt.Errorf("key is not password-protected: keys are required to be password-protected")
	}

	key, err := parsePrivateKey(bts, nil)
	if err != nil && isPasswordError(err) {
		// Key requires a password - ask for it and parse again with the same bytes
		pass, err := askKeyPassphrase(keyPath)
		if err != nil {
			return err
		}
		// Parse again with the password using the bytes we already have
		key, err = parsePrivateKey(bts, pass)
		if err != nil {
			return fmt.Errorf("could not parse key with passphrase: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("could not parse key: %w", err)
	}

	ed25519Key, ok := key.(*ed25519.PrivateKey)
	if !ok {
		return fmt.Errorf("unknown key type: %v", key)
	}

	// Generate and display outputs for each word count
	for i, count := range wordCounts {
		// Generate seed phrase
		mnemonic, err := seedify.ToMnemonicWithLength(ed25519Key, count, seedPassphrase, false)
		if err != nil {
			return fmt.Errorf("could not generate %d-word mnemonic: %w", count, err)
		}

		// Display seed phrase
		fmt.Printf("[%d word seed phrase]\n", count)
		fmt.Println()
		fmt.Println(mnemonic)
		fmt.Println()

		// Derive and display Monero addresses for 16-word polyseed
		if count == 16 && deriveXmr {
			// Generate primary address plus 9 subaddresses
			xmrKeys, err := seedify.DeriveMoneroKeys(mnemonic, 9) //nolint:mnd
			if err != nil {
				return fmt.Errorf("failed to derive Monero keys from 16-word polyseed: %w", err)
			}

			fmt.Printf("[monero addresses from 16 word polyseed]\n")
			fmt.Println()
			fmt.Printf("%s (primary address)\n", xmrKeys.PrimaryAddress)
			for i, subaddr := range xmrKeys.Subaddresses {
				fmt.Printf("> %s (subaddress 0,%d)\n", subaddr, i+1)
			}
			fmt.Println()
		}

		// Derive and display nostr keys for 12-word and 24-word seed phrases only
		if deriveNostr && (count == 12 || count == 24) {
			nostrKeys, err := seedify.DeriveNostrKeysWithHex(mnemonic, "")
			if err != nil {
				return fmt.Errorf("failed to derive Nostr keys from %d-word mnemonic: %w", count, err)
			}

			fmt.Printf("[nostr keys from %d word seed]\n", count)
			fmt.Println()
			fmt.Printf("%s (nostr public key aka \"nostr user\")\n", nostrKeys.Npub)
			fmt.Printf("└─ %s (hex)\n", nostrKeys.PubKeyHex)
			fmt.Printf("%s (nostr secret key aka \"nostr pass\")\n", nostrKeys.Nsec)
			fmt.Printf("└─ %s (hex)\n", nostrKeys.PrivKeyHex)
			fmt.Println()
		}

		// Derive and display Bitcoin keys for 12 or 24-word seed phrase
		if (count == 12 || count == 24) && deriveBtc {
			// Derive all Bitcoin keys and extended keys
			if err := displayBitcoinOutput(mnemonic, count); err != nil {
				return err
			}
		}

		// Derive and display Ethereum/Solana/Tron and other chain addresses for 24-word seed phrase only.
		// Extra chains (Litecoin, Dogecoin, Cosmos, Noble, Sui, Stellar, Ripple) are only shown when
		// the user has requested at least one crypto derivation via --btc, --eth, --sol, or --tron.
		// This keeps --words 24 output minimal when no derivation flags are passed.
		if count == 24 { //nolint:mnd,nestif
			hasAnyCryptoFlag := deriveBtc || deriveEth || deriveZec || deriveSol || deriveTron

			// Ethereum address
			if deriveEth {
				ethAddr, err := seedify.DeriveEthereumAddress(mnemonic, "")
				if err != nil {
					return fmt.Errorf("failed to derive Ethereum address from 24-word seed: %w", err)
				}

				fmt.Printf("[ethereum address from 24 word seed]\n")
				fmt.Println()
				fmt.Println(ethAddr)
				fmt.Println()
			}

			// Zcash address (below Ethereum, shown when any crypto derivation is requested)
			if hasAnyCryptoFlag {
				zcashAddr, err := seedify.DeriveZcashAddress(mnemonic, "")
				if err != nil {
					return fmt.Errorf("failed to derive Zcash address from 24-word seed: %w", err)
				}

				fmt.Printf("[zcash address from 24 word seed]\n")
				fmt.Println()
				fmt.Println(zcashAddr)
				fmt.Println()
			}

			// Solana address
			if deriveSol {
				solAddr, err := seedify.DeriveSolanaAddress(mnemonic, "")
				if err != nil {
					return fmt.Errorf("failed to derive Solana address from 24-word seed: %w", err)
				}

				fmt.Printf("[solana address from 24 word seed]\n")
				fmt.Println()
				fmt.Println(solAddr)
				fmt.Println()
			}

			// Tron address
			if deriveTron {
				tronAddr, err := seedify.DeriveTronAddress(mnemonic, "")
				if err != nil {
					return fmt.Errorf("failed to derive Tron address from 24-word seed: %w", err)
				}

				fmt.Printf("[tron address from 24 word seed]\n")
				fmt.Println()
				fmt.Println(tronAddr)
				fmt.Println()
			}

			// EVM-compatible chain addresses (reuse Ethereum address)
			if deriveEth {
				evmAddr, evmErr := seedify.DeriveEthereumAddress(mnemonic, "")
				if evmErr != nil {
					return fmt.Errorf("failed to derive EVM address from 24-word seed: %w", evmErr)
				}

				fmt.Printf("[arbitrum address from 24 word seed]\n")
				fmt.Println()
				fmt.Println(evmAddr)
				fmt.Println()

				fmt.Printf("[avalanche address from 24 word seed]\n")
				fmt.Println()
				fmt.Println(evmAddr)
				fmt.Println()

				fmt.Printf("[base address from 24 word seed]\n")
				fmt.Println()
				fmt.Println(evmAddr)
				fmt.Println()

				fmt.Printf("[bnbchain address from 24 word seed]\n")
				fmt.Println()
				fmt.Println(evmAddr)
				fmt.Println()

				fmt.Printf("[cronos address from 24 word seed]\n")
				fmt.Println()
				fmt.Println(evmAddr)
				fmt.Println()

				fmt.Printf("[optimism address from 24 word seed]\n")
				fmt.Println()
				fmt.Println(evmAddr)
				fmt.Println()

				fmt.Printf("[polygon address from 24 word seed]\n")
				fmt.Println()
				fmt.Println(evmAddr)
				fmt.Println()
			}

			// Extra chains: only show when user requested at least one crypto derivation
			if hasAnyCryptoFlag {
				// Litecoin address (native SegWit)
				ltcAddr, err := seedify.DeriveLitecoinAddress(mnemonic, "")
				if err != nil {
					return fmt.Errorf("failed to derive Litecoin address from 24-word seed: %w", err)
				}

				fmt.Printf("[litecoin address from 24 word seed]\n")
				fmt.Println()
				fmt.Println(ltcAddr)
				fmt.Println()

				// Dogecoin address
				dogeAddr, err := seedify.DeriveDogecoinAddress(mnemonic, "")
				if err != nil {
					return fmt.Errorf("failed to derive Dogecoin address from 24-word seed: %w", err)
				}

				fmt.Printf("[dogecoin address from 24 word seed]\n")
				fmt.Println()
				fmt.Println(dogeAddr)
				fmt.Println()

				// Cosmos address
				cosmosAddr, err := seedify.DeriveCosmosAddress(mnemonic, "")
				if err != nil {
					return fmt.Errorf("failed to derive Cosmos address from 24-word seed: %w", err)
				}

				fmt.Printf("[cosmos address from 24 word seed]\n")
				fmt.Println()
				fmt.Println(cosmosAddr)
				fmt.Println()

				// Noble address
				nobleAddr, err := seedify.DeriveNobleAddress(mnemonic, "")
				if err != nil {
					return fmt.Errorf("failed to derive Noble address from 24-word seed: %w", err)
				}

				fmt.Printf("[noble address from 24 word seed]\n")
				fmt.Println()
				fmt.Println(nobleAddr)
				fmt.Println()

				// Sui address
				suiAddr, err := seedify.DeriveSuiAddress(mnemonic, "")
				if err != nil {
					return fmt.Errorf("failed to derive Sui address from 24-word seed: %w", err)
				}

				fmt.Printf("[sui address from 24 word seed]\n")
				fmt.Println()
				fmt.Println(suiAddr)
				fmt.Println()

				// Stellar address
				xlmAddr, err := seedify.DeriveStellarAddress(mnemonic, "")
				if err != nil {
					return fmt.Errorf("failed to derive Stellar address from 24-word seed: %w", err)
				}

				fmt.Printf("[stellar address from 24 word seed]\n")
				fmt.Println()
				fmt.Println(xlmAddr)
				fmt.Println()

				// Ripple address
				xrpAddr, err := seedify.DeriveRippleAddress(mnemonic, "")
				if err != nil {
					return fmt.Errorf("failed to derive Ripple address from 24-word seed: %w", err)
				}

				fmt.Printf("[ripple address from 24 word seed]\n")
				fmt.Println()
				fmt.Println(xrpAddr)
				fmt.Println()
			}
		}

		// Add blank line between word counts (except after the last one, unless brave is also shown)
		if i < len(wordCounts)-1 || showBrave {
			fmt.Println()
		}
	}

	// Display brave 25-word seed phrase at the end if requested
	if showBrave {
		braveMnemonic, err := seedify.ToMnemonicWithBraveSync(ed25519Key, seedPassphrase)
		if err != nil {
			return fmt.Errorf("could not generate brave 25-word mnemonic: %w", err)
		}

		fmt.Printf("[25 word brave seed phrase]\n")
		fmt.Println()
		fmt.Println(braveMnemonic)
		fmt.Println()
	}

	return nil
}

// parseWordCounts parses a comma-separated string of word counts and validates them.
// Valid word counts are: 12, 15, 16, 18, 21, or 24.
func parseWordCounts(wordCountStr string) ([]int, error) {
	if wordCountStr == "" {
		return []int{12, 15, 16, 18, 21, 24}, nil
	}

	validCounts := map[int]bool{12: true, 15: true, 16: true, 18: true, 21: true, 24: true}
	parts := strings.Split(wordCountStr, ",")
	wordCounts := make([]int, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		count, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid word count %q: %w", part, err)
		}

		if !validCounts[count] {
			return nil, fmt.Errorf("invalid word count: %d (must be 12, 15, 16, 18, 21, or 24)", count)
		}

		wordCounts = append(wordCounts, count)
	}

	if len(wordCounts) == 0 {
		return []int{12, 15, 16, 18, 21, 24}, nil
	}

	return wordCounts, nil
}

func askKeyPassphrase(path string) ([]byte, error) {
	defer fmt.Fprintf(os.Stderr, "\n")
	return readPassword(fmt.Sprintf("Enter the passphrase to unlock %q: ", path))
}

// displayBitcoinOutput displays all Bitcoin derivations for a given mnemonic.
// This includes addresses with private keys, extended keys, and multisig addresses.
//
//nolint:funlen
func displayBitcoinOutput(mnemonic string, wordCount int) error {
	// === MASTER EXTENDED KEYS ===
	// The master key is the root of the HD wallet tree (path: m)
	// This is the same key regardless of which BIP standard you're using

	masterExtended, err := seedify.DeriveBitcoinMasterExtendedKeys(mnemonic, "")
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin master extended keys: %w", err)
	}

	fmt.Printf("[bitcoin master extended keys from %d word seed]\n", wordCount)
	fmt.Println()
	fmt.Printf("%s (master xpub at m)\n", masterExtended.ExtendedPublicKey)
	fmt.Printf("%s (master xprv at m)\n", masterExtended.ExtendedPrivateKey)
	fmt.Println()

	// === SINGLE-SIG ADDRESSES AND PRIVATE KEYS ===

	// Legacy P2PKH (BIP44)
	legacyKeys, err := seedify.DeriveBitcoinLegacyKeys(mnemonic, "")
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin legacy keys: %w", err)
	}

	// SegWit P2SH-P2WPKH (BIP49)
	segwitKeys, err := seedify.DeriveBitcoinSegwitKeys(mnemonic, "")
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin SegWit keys: %w", err)
	}

	// Native SegWit P2WPKH (BIP84)
	nativeKeys, err := seedify.DeriveBitcoinNativeSegwitKeys(mnemonic, "")
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin native SegWit keys: %w", err)
	}

	fmt.Printf("[bitcoin addresses from %d word seed]\n", wordCount)
	fmt.Println()
	fmt.Printf("%s (legacy P2PKH - BIP44 m/44'/0'/0'/0/0)\n", legacyKeys.Address)
	fmt.Printf("%s (segwit P2SH-P2WPKH - BIP49 m/49'/0'/0'/0/0)\n", segwitKeys.Address)
	fmt.Printf("%s (native segwit P2WPKH - BIP84 m/84'/0'/0'/0/0)\n", nativeKeys.Address)
	fmt.Println()

	// === PRIVATE KEYS (WIF) ===

	fmt.Printf("[bitcoin private keys from %d word seed]\n", wordCount)
	fmt.Println()
	fmt.Printf("%s (legacy P2PKH - BIP44)\n", legacyKeys.PrivateWIF)
	fmt.Printf("%s (segwit P2SH-P2WPKH - BIP49)\n", segwitKeys.PrivateWIF)
	fmt.Printf("%s (native segwit P2WPKH - BIP84)\n", nativeKeys.PrivateWIF)
	fmt.Println()

	// === ACCOUNT-LEVEL EXTENDED KEYS ===
	// These are derived to the account level for each BIP standard
	// Import these into wallets to derive all addresses for that account

	// Legacy extended keys (xpub/xprv)
	legacyExtended, err := seedify.DeriveBitcoinLegacyExtendedKeys(mnemonic, "")
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin legacy extended keys: %w", err)
	}

	// SegWit extended keys (ypub/yprv)
	segwitExtended, err := seedify.DeriveBitcoinSegwitExtendedKeys(mnemonic, "")
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin SegWit extended keys: %w", err)
	}

	// Native SegWit extended keys (zpub/zprv)
	nativeExtended, err := seedify.DeriveBitcoinNativeSegwitExtendedKeys(mnemonic, "")
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin native SegWit extended keys: %w", err)
	}

	fmt.Printf("[bitcoin account extended public keys from %d word seed]\n", wordCount)
	fmt.Println()
	fmt.Printf("%s (legacy account xpub - BIP44 m/44'/0'/0')\n", legacyExtended.ExtendedPublicKey)
	fmt.Printf("%s (segwit account ypub - BIP49 m/49'/0'/0')\n", segwitExtended.ExtendedPublicKey)
	fmt.Printf("%s (native segwit account zpub - BIP84 m/84'/0'/0')\n", nativeExtended.ExtendedPublicKey)
	fmt.Println()

	fmt.Printf("[bitcoin account extended private keys from %d word seed]\n", wordCount)
	fmt.Println()
	fmt.Printf("%s (legacy account xprv - BIP44 m/44'/0'/0')\n", legacyExtended.ExtendedPrivateKey)
	fmt.Printf("%s (segwit account yprv - BIP49 m/49'/0'/0')\n", segwitExtended.ExtendedPrivateKey)
	fmt.Printf("%s (native segwit account zprv - BIP84 m/84'/0'/0')\n", nativeExtended.ExtendedPrivateKey)
	fmt.Println()

	// === MULTISIG 1-OF-1 ADDRESSES AND PRIVATE KEYS ===

	// Legacy multisig P2SH (BIP48)
	multisigLegacyKeys, err := seedify.DeriveBitcoinMultisigLegacyKeys(mnemonic, "")
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin multisig legacy keys: %w", err)
	}

	// SegWit multisig P2SH-P2WSH (BIP48)
	multisigSegwitKeys, err := seedify.DeriveBitcoinMultisigSegwitKeys(mnemonic, "")
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin multisig SegWit keys: %w", err)
	}

	// Native SegWit multisig P2WSH (BIP48)
	multisigNativeKeys, err := seedify.DeriveBitcoinMultisigNativeSegwitKeys(mnemonic, "")
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin multisig native SegWit keys: %w", err)
	}

	fmt.Printf("[bitcoin multisig 1-of-1 addresses from %d word seed]\n", wordCount)
	fmt.Println()
	fmt.Printf("%s (legacy P2SH - BIP48 m/48'/0'/0'/0'/0/0)\n", multisigLegacyKeys.Address)
	fmt.Printf("%s (segwit P2SH-P2WSH - BIP48 m/48'/0'/0'/1'/0/0)\n", multisigSegwitKeys.Address)
	fmt.Printf("%s (native segwit P2WSH - BIP48 m/48'/0'/0'/2'/0/0)\n", multisigNativeKeys.Address)
	fmt.Println()

	fmt.Printf("[bitcoin multisig 1-of-1 private keys from %d word seed]\n", wordCount)
	fmt.Println()
	fmt.Printf("%s (legacy P2SH - BIP48)\n", multisigLegacyKeys.PrivateWIF)
	fmt.Printf("%s (segwit P2SH-P2WSH - BIP48)\n", multisigSegwitKeys.PrivateWIF)
	fmt.Printf("%s (native segwit P2WSH - BIP48)\n", multisigNativeKeys.PrivateWIF)
	fmt.Println()

	// === MULTISIG ACCOUNT-LEVEL EXTENDED KEYS ===

	// Legacy multisig extended keys (xpub/xprv)
	multisigLegacyExtended, err := seedify.DeriveBitcoinMultisigLegacyExtendedKeys(mnemonic, "")
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin multisig legacy extended keys: %w", err)
	}

	// SegWit multisig extended keys (Ypub/Yprv)
	multisigSegwitExtended, err := seedify.DeriveBitcoinMultisigSegwitExtendedKeys(mnemonic, "")
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin multisig SegWit extended keys: %w", err)
	}

	// Native SegWit multisig extended keys (Zpub/Zprv)
	multisigNativeExtended, err := seedify.DeriveBitcoinMultisigNativeSegwitExtendedKeys(mnemonic, "")
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin multisig native SegWit extended keys: %w", err)
	}

	fmt.Printf("[bitcoin multisig 1-of-1 account extended public keys from %d word seed]\n", wordCount)
	fmt.Println()
	fmt.Printf("%s (legacy account xpub - BIP48 m/48'/0'/0'/0')\n", multisigLegacyExtended.ExtendedPublicKey)
	fmt.Printf("%s (segwit account Ypub - BIP48 m/48'/0'/0'/1')\n", multisigSegwitExtended.ExtendedPublicKey)
	fmt.Printf("└─ %s (xpub)\n", multisigSegwitExtended.StandardPublicKey)
	fmt.Printf("%s (native segwit account Zpub - BIP48 m/48'/0'/0'/2')\n", multisigNativeExtended.ExtendedPublicKey)
	fmt.Printf("└─ %s (xpub)\n", multisigNativeExtended.StandardPublicKey)
	fmt.Println()

	fmt.Printf("[bitcoin multisig 1-of-1 account extended private keys from %d word seed]\n", wordCount)
	fmt.Println()
	fmt.Printf("%s (legacy account xprv - BIP48 m/48'/0'/0'/0')\n", multisigLegacyExtended.ExtendedPrivateKey)
	fmt.Printf("%s (segwit account Yprv - BIP48 m/48'/0'/0'/1')\n", multisigSegwitExtended.ExtendedPrivateKey)
	fmt.Printf("└─ %s (xprv)\n", multisigSegwitExtended.StandardPrivateKey)
	fmt.Printf("%s (native segwit account Zprv - BIP48 m/48'/0'/0'/2')\n", multisigNativeExtended.ExtendedPrivateKey)
	fmt.Printf("└─ %s (xprv)\n", multisigNativeExtended.StandardPrivateKey)
	fmt.Println()

	return nil
}

// dnsRecord represents the JSON structure for DNS output.
// Fields are ordered to match the expected DNS JSON format.
//
//nolint:govet
type dnsRecord struct {
	SSHEd25519    string `json:"ssh-ed25519"`
	Nostr         string `json:"nostr"`
	Npub          string `json:"npub"`
	NpubKey       string `json:"npubkey"`
	PubKey        string `json:"pubkey"`
	HexPub        string `json:"hexpub"`
	HexPubKey     string `json:"hexpubkey"`
	Bitcoin       string `json:"bitcoin"`
	SilentPayment string `json:"silentpayment"`
	Litecoin      string `json:"litecoin"`
	Dogecoin      string `json:"dogecoin"`
	Monero        string `json:"monero"`
	Cosmos        string `json:"cosmos"`
	Noble         string `json:"noble"`
	Arbitrum      string `json:"arbitrum"`
	Avalanche     string `json:"avalanche"`
	Base          string `json:"base"`
	BNBChain      string `json:"bnbchain"`
	Cronos        string `json:"cronos"`
	Ethereum      string `json:"ethereum"`
	Zcash         string `json:"zcash"`
	Optimism      string `json:"optimism"`
	Polygon       string `json:"polygon"`
	Solana        string `json:"solana"`
	Sui           string `json:"sui"`
	Tron          string `json:"tron"`
	Stellar       string `json:"stellar"`
	Ripple        string `json:"ripple"`
}

// tagsToNostrTags converts [][]string to nostrpkg.Tags ([]nostrpkg.Tag).
func tagsToNostrTags(tags [][]string) nostrpkg.Tags {
	out := make(nostrpkg.Tags, len(tags))
	for i, t := range tags {
		out[i] = nostrpkg.Tag(t)
	}
	return out
}

// dnsRecordToNIP78Tags converts a dnsRecord to NIP-78 Kind 30078 compliant tags.
// Adds ["d", appID] first, then ["name", value] for each non-empty field.
func dnsRecordToNIP78Tags(record dnsRecord, appID string) [][]string {
	addTag := func(tags *[][]string, name, value string) {
		if value != "" {
			*tags = append(*tags, []string{name, value})
		}
	}
	tags := [][]string{{"d", appID}}
	addTag(&tags, "ssh-ed25519", record.SSHEd25519)
	addTag(&tags, "nostr", record.Nostr)
	addTag(&tags, "npub", record.Npub)
	addTag(&tags, "npubkey", record.NpubKey)
	addTag(&tags, "pubkey", record.PubKey)
	addTag(&tags, "hexpub", record.HexPub)
	addTag(&tags, "hexpubkey", record.HexPubKey)
	addTag(&tags, "bitcoin", record.Bitcoin)
	addTag(&tags, "silentpayment", record.SilentPayment)
	addTag(&tags, "litecoin", record.Litecoin)
	addTag(&tags, "dogecoin", record.Dogecoin)
	addTag(&tags, "monero", record.Monero)
	addTag(&tags, "cosmos", record.Cosmos)
	addTag(&tags, "noble", record.Noble)
	addTag(&tags, "arbitrum", record.Arbitrum)
	addTag(&tags, "avalanche", record.Avalanche)
	addTag(&tags, "base", record.Base)
	addTag(&tags, "bnbchain", record.BNBChain)
	addTag(&tags, "cronos", record.Cronos)
	addTag(&tags, "ethereum", record.Ethereum)
	addTag(&tags, "zcash", record.Zcash)
	addTag(&tags, "optimism", record.Optimism)
	addTag(&tags, "polygon", record.Polygon)
	addTag(&tags, "solana", record.Solana)
	addTag(&tags, "sui", record.Sui)
	addTag(&tags, "tron", record.Tron)
	addTag(&tags, "stellar", record.Stellar)
	addTag(&tags, "ripple", record.Ripple)
	return tags
}

// normalizeRelayURL prepends wss:// when no scheme is present; accepts wss:// and ws:// as-is.
func normalizeRelayURL(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "wss://") || strings.HasPrefix(s, "ws://") {
		return s
	}
	return "wss://" + s
}

// parseRelayURLs splits a comma-separated relay string and returns normalized wss:// URLs.
// Empty entries are skipped.
func parseRelayURLs(relaysStr string) []string {
	if relaysStr == "" {
		return nil
	}
	parts := strings.Split(relaysStr, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		url := normalizeRelayURL(p)
		if url != "" {
			out = append(out, url)
		}
	}
	return out
}

// randUint32n returns a cryptographically random uint32 in [0, n) using crypto/rand.
func randUint32n(n uint32) uint32 {
	if n == 0 {
		return 0
	}
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return binary.BigEndian.Uint32(b[:]) % n
}

// generateDNSRecord parses the key, derives addresses, and returns the dnsRecord and Nostr keys.
//
//nolint:funlen
func generateDNSRecord(keyPath string, seedPassphrase string) (*dnsRecord, *seedify.NostrKeys, error) {
	// Parse the key (same pattern as generateUnifiedOutput)
	f, err := openFileOrStdin(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("could not read key: %w", err)
	}
	defer f.Close() //nolint:errcheck
	bts, err := io.ReadAll(f)
	if err != nil {
		return nil, nil, fmt.Errorf("could not read key: %w", err)
	}

	// Check if key is password-protected (required for this command)
	isProtected, err := isKeyPasswordProtected(bts)
	if err == nil && !isProtected {
		return nil, nil, errors.New("key is not password-protected: keys are required to be password-protected")
	}

	key, err := parsePrivateKey(bts, nil)
	if err != nil && isPasswordError(err) {
		pass, passErr := askKeyPassphrase(keyPath)
		if passErr != nil {
			return nil, nil, passErr
		}
		key, err = parsePrivateKey(bts, pass)
		if err != nil {
			return nil, nil, fmt.Errorf("could not parse key with passphrase: %w", err)
		}
	} else if err != nil {
		return nil, nil, fmt.Errorf("could not parse key: %w", err)
	}

	ed25519Key, ok := key.(*ed25519.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("unknown key type: %v", key)
	}

	sshPubKey, err := ssh.NewPublicKey(ed25519Key.Public())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create SSH public key: %w", err)
	}
	sshPubKeyBase64 := base64.StdEncoding.EncodeToString(sshPubKey.Marshal())

	mnemonic, err := seedify.ToMnemonicWithLength(ed25519Key, 24, seedPassphrase, false) //nolint:mnd
	if err != nil {
		return nil, nil, fmt.Errorf("could not generate 24-word mnemonic: %w", err)
	}

	nostrKeys, err := seedify.DeriveNostrKeysWithHex(mnemonic, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Nostr keys: %w", err)
	}

	btcIdx := 1 + randUint32n(19) //nolint:mnd
	btcAddr, err := seedify.DeriveBitcoinAddressNativeSegwitAtIndex(mnemonic, "", btcIdx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Bitcoin native SegWit address: %w", err)
	}

	sp1Addr, err := seedify.DeriveSilentPaymentAddress(mnemonic, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Silent Payment (sp1) address: %w", err)
	}

	ltcAddr, err := seedify.DeriveLitecoinAddress(mnemonic, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Litecoin address: %w", err)
	}

	dogeAddr, err := seedify.DeriveDogecoinAddress(mnemonic, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Dogecoin address: %w", err)
	}

	polyseedMnemonic, err := seedify.ToMnemonicWithLength(ed25519Key, 16, seedPassphrase, false) //nolint:mnd
	if err != nil {
		return nil, nil, fmt.Errorf("could not generate 16-word polyseed: %w", err)
	}
	xmrIdx := randUint32n(20) //nolint:mnd
	xmrAddr, err := seedify.DeriveMoneroSubaddressAtIndex(polyseedMnemonic, xmrIdx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Monero address: %w", err)
	}

	cosmosAddr, err := seedify.DeriveCosmosAddress(mnemonic, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Cosmos address: %w", err)
	}

	nobleAddr, err := seedify.DeriveNobleAddress(mnemonic, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Noble address: %w", err)
	}

	ethAddr, err := seedify.DeriveEthereumAddress(mnemonic, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Ethereum address: %w", err)
	}

	zcashAddr, err := seedify.DeriveZcashAddress(mnemonic, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Zcash address: %w", err)
	}

	solAddr, err := seedify.DeriveSolanaAddress(mnemonic, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Solana address: %w", err)
	}

	suiAddr, err := seedify.DeriveSuiAddress(mnemonic, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Sui address: %w", err)
	}

	tronAddr, err := seedify.DeriveTronAddress(mnemonic, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Tron address: %w", err)
	}

	xlmAddr, err := seedify.DeriveStellarAddress(mnemonic, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Stellar address: %w", err)
	}

	xrpAddr, err := seedify.DeriveRippleAddress(mnemonic, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Ripple address: %w", err)
	}

	record := &dnsRecord{
		SSHEd25519:    sshPubKeyBase64,
		Nostr:         nostrKeys.Npub,
		Npub:          nostrKeys.Npub,
		NpubKey:       nostrKeys.Npub,
		PubKey:        nostrKeys.PubKeyHex,
		HexPub:        nostrKeys.PubKeyHex,
		HexPubKey:     nostrKeys.PubKeyHex,
		Bitcoin:       btcAddr,
		SilentPayment: sp1Addr,
		Litecoin:      ltcAddr,
		Dogecoin:      dogeAddr,
		Monero:        xmrAddr,
		Cosmos:        cosmosAddr,
		Noble:         nobleAddr,
		Arbitrum:      ethAddr,
		Avalanche:     ethAddr,
		Base:          ethAddr,
		BNBChain:      ethAddr,
		Cronos:        ethAddr,
		Ethereum:      ethAddr,
		Zcash:         zcashAddr,
		Optimism:      ethAddr,
		Polygon:       ethAddr,
		Solana:        solAddr,
		Sui:           suiAddr,
		Tron:          tronAddr,
		Stellar:       xlmAddr,
		Ripple:        xrpAddr,
	}
	return record, nostrKeys, nil
}

// publishDNSToRelays builds a NIP-78 Kind 30078 event from the dnsRecord and publishes it to the given relays.
func publishDNSToRelays(record *dnsRecord, nostrKeys *seedify.NostrKeys, relays []string) error {
	appID := zenprofileAppID
	if appID == "" {
		appID = "app.zenprofile.contactme"
	}
	tags := dnsRecordToNIP78Tags(*record, appID)
	const kindNIP78 = 30078
	ev := nostrpkg.Event{
		PubKey:    nostrKeys.PubKeyHex,
		CreatedAt: nostrpkg.Now(),
		Kind:      kindNIP78,
		Tags:      tagsToNostrTags(tags),
		Content:   "",
	}
	if err := ev.Sign(nostrKeys.PrivKeyHex); err != nil {
		return fmt.Errorf("failed to sign NIP-78 Kind 30078 event: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) //nolint:mnd
	defer cancel()

	for _, url := range relays {
		relay, err := nostrpkg.RelayConnect(ctx, url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "seedify: failed to connect to %s: %v\n", url, err)
			continue
		}
		if err := relay.Publish(ctx, ev); err != nil {
			fmt.Fprintf(os.Stderr, "seedify: failed to publish to %s: %v\n", url, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "seedify: published NIP-78 Kind 30078 to %s\n", url)
	}
	return nil
}
