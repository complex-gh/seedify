// Package main provides the seedify CLI tool for generating seed phrases from SSH keys.
package main

import (
	"context"
	"crypto/ed25519"
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

	language       string
	wordCountStr   string
	seedPassphrase string
	brave          bool
	nostr          bool
	bitcoin        bool
	ethereum       bool
	solana         bool
	monero         bool

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

			// Check if any derivation flags were explicitly provided
			hasWordsFlag := wordCountStr != ""
			hasNostrFlag := nostr
			hasCryptoFlags := bitcoin || ethereum || solana || monero
			hasAnyDerivationFlags := hasWordsFlag || hasNostrFlag || hasCryptoFlags

			// Determine which derivations to show
			// If no flags provided: show all derivations (all word counts + nostr + brave)
			// If flags provided: show only specified derivations
			var wordCounts []int
			var deriveNostr bool
			var showBrave bool
			var deriveBtc, deriveEth, deriveSol, deriveXmr bool

			if !hasAnyDerivationFlags {
				// No flags provided - show all derivations including brave seed at the end
				wordCounts = []int{12, 15, 16, 18, 21, 24}
				deriveNostr = true
				showBrave = true
				// Derive all crypto addresses by default
				deriveBtc = true
				deriveEth = true
				deriveSol = true
				deriveXmr = true
			} else {
				// Flags provided - show only specified derivations
				if hasWordsFlag {
					// Parse word counts from flag
					parsedCounts, err := parseWordCounts(wordCountStr)
					if err != nil {
						return fmt.Errorf("invalid word counts: %w", err)
					}
					wordCounts = parsedCounts
				} else if hasCryptoFlags {
					// If crypto flags are set but no word counts, ensure we have the needed word counts
					// BTC needs 12 and 24 words; ETH, SOL need 24 words; XMR needs 16 words
					wordCounts = []int{}
					if bitcoin {
						wordCounts = append(wordCounts, 12) //nolint:mnd
					}
					if monero {
						wordCounts = append(wordCounts, 16) //nolint:mnd
					}
					if bitcoin || ethereum || solana {
						wordCounts = append(wordCounts, 24) //nolint:mnd
					}
				}
				// Only derive nostr if the flag was explicitly set
				deriveNostr = hasNostrFlag
				// Don't show brave seed when specific flags are provided
				showBrave = false
				// Set crypto derivation flags
				deriveBtc = bitcoin
				deriveEth = ethereum
				deriveSol = solana
				deriveXmr = monero
			}

			// Generate unified output (seed phrases + wallet derivations)
			err := generateUnifiedOutput(keyPath, wordCounts, seedPassphrase, deriveNostr, showBrave, deriveBtc, deriveEth, deriveSol, deriveXmr)
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
	rootCmd.PersistentFlags().BoolVar(&nostr, "nostr", false, "Derive Nostr keys (npub/nsec) from seed phrase.")
	rootCmd.PersistentFlags().BoolVar(&bitcoin, "btc", false, "Derive Bitcoin address from 24-word seed phrase")
	rootCmd.PersistentFlags().BoolVar(&ethereum, "eth", false, "Derive Ethereum address from 24-word seed phrase")
	rootCmd.PersistentFlags().BoolVar(&solana, "sol", false, "Derive Solana address from 24-word seed phrase")
	rootCmd.PersistentFlags().BoolVar(&monero, "xmr", false, "Derive Monero address from 16-word polyseed")
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
// Crypto address flags (deriveBtc, deriveEth, deriveSol, deriveXmr) control which addresses to derive.
func generateUnifiedOutput(keyPath string, wordCounts []int, seedPassphrase string, deriveNostr bool, showBrave bool, deriveBtc, deriveEth, deriveSol, deriveXmr bool) error {
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

		// Derive and display Monero address for 16-word polyseed
		if count == 16 && deriveXmr {
			xmrAddr, err := seedify.DeriveMoneroAddress(mnemonic)
			if err != nil {
				return fmt.Errorf("failed to derive Monero address from 16-word polyseed: %w", err)
			}

			fmt.Printf("[monero address from 16 word polyseed]\n")
			fmt.Println()
			fmt.Println(xmrAddr)
			fmt.Println()
		}

		// Derive and display nostr keys for 12-word and 24-word seed phrases only
		if deriveNostr && (count == 12 || count == 24) {
			npub, nsec, err := seedify.DeriveNostrKeys(mnemonic, "")
			if err != nil {
				return fmt.Errorf("failed to derive Nostr keys from %d-word mnemonic: %w", count, err)
			}

			fmt.Printf("[nostr keys from %d word seed]\n", count)
			fmt.Println()
			fmt.Printf("%s (nostr public key aka \"nostr user\")\n", npub)
			fmt.Printf("%s (nostr secret key aka \"nostr pass\")\n", nsec)
			fmt.Println()
		}

		// Derive and display Bitcoin keys for 12 or 24-word seed phrase
		if (count == 12 || count == 24) && deriveBtc { //nolint:mnd,nestif
			// Derive all Bitcoin keys and extended keys
			if err := displayBitcoinOutput(mnemonic, count); err != nil {
				return err
			}
		}

		// Derive and display Ethereum/Solana addresses for 24-word seed phrase only
		if count == 24 { //nolint:mnd,nestif
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

	// Taproot P2TR (BIP86) - address only, no extended keys per spec
	taprootAddr, err := seedify.DeriveBitcoinAddressTaproot(mnemonic, "")
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin Taproot address: %w", err)
	}

	fmt.Printf("[bitcoin addresses from %d word seed]\n", wordCount)
	fmt.Println()
	fmt.Printf("%s (legacy P2PKH - BIP44 m/44'/0'/0'/0/0)\n", legacyKeys.Address)
	fmt.Printf("%s (segwit P2SH-P2WPKH - BIP49 m/49'/0'/0'/0/0)\n", segwitKeys.Address)
	fmt.Printf("%s (native segwit P2WPKH - BIP84 m/84'/0'/0'/0/0)\n", nativeKeys.Address)
	fmt.Printf("%s (taproot P2TR - BIP86 m/86'/0'/0'/0/0)\n", taprootAddr)
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
	fmt.Printf("%s (segwit P2SH-P2WSH - BIP48 m/48'/0'/0'/1'/0/0)\n", multisigSegwitKeys.Address)
	fmt.Printf("%s (native segwit P2WSH - BIP48 m/48'/0'/0'/2'/0/0)\n", multisigNativeKeys.Address)
	fmt.Println()

	fmt.Printf("[bitcoin multisig 1-of-1 private keys from %d word seed]\n", wordCount)
	fmt.Println()
	fmt.Printf("%s (segwit P2SH-P2WSH - BIP48)\n", multisigSegwitKeys.PrivateWIF)
	fmt.Printf("%s (native segwit P2WSH - BIP48)\n", multisigNativeKeys.PrivateWIF)
	fmt.Println()

	// === MULTISIG ACCOUNT-LEVEL EXTENDED KEYS ===
	// Note: BIP48 only defines script types 1' (P2SH-P2WSH) and 2' (P2WSH)
	// Legacy P2SH multisig (script type 0') is not part of BIP48 standard

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
	fmt.Printf("%s (segwit account Ypub - BIP48 m/48'/0'/0'/1')\n", multisigSegwitExtended.ExtendedPublicKey)
	fmt.Printf("%s (native segwit account Zpub - BIP48 m/48'/0'/0'/2')\n", multisigNativeExtended.ExtendedPublicKey)
	fmt.Println()

	fmt.Printf("[bitcoin multisig 1-of-1 account extended private keys from %d word seed]\n", wordCount)
	fmt.Println()
	fmt.Printf("%s (segwit account Yprv - BIP48 m/48'/0'/0'/1')\n", multisigSegwitExtended.ExtendedPrivateKey)
	fmt.Printf("%s (native segwit account Zprv - BIP48 m/48'/0'/0'/2')\n", multisigNativeExtended.ExtendedPrivateKey)
	fmt.Println()

	return nil
}
