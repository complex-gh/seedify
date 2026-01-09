package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
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
	baseStyle = lipgloss.NewStyle().Margin(0, 0, 1, 2) //nolint: gomnd
	violet    = lipgloss.Color(completeColor("#6B50FF", "63", "12"))
	red       = lipgloss.Color(completeColor("#FF4444", "196", "9"))
	mnemonicStyle = baseStyle.
			Foreground(violet).
			Background(lipgloss.AdaptiveColor{Light: completeColor("#EEEBFF", "255", "7"), Dark: completeColor("#1B1731", "235", "8")}).
			Padding(1, 2) //nolint: gomnd
	errorStyle = baseStyle.
			Foreground(red).
			Background(lipgloss.AdaptiveColor{Light: completeColor("#FFEBEB", "255", "7"), Dark: completeColor("#2B1A1A", "235", "8")}).
			Padding(1, 2) //nolint: gomnd

	language string
	wordCount int
	raw      bool
	all      bool
	seedPassphrase string
	brave    bool

	rootCmd = &cobra.Command{
		Use:   "seedify",
		Short: "Generate a seed phrase from an SSH key",
		Long: `Generate a seed phrase from an SSH key.

Valid word counts are: 12, 15, 16, 18, 21, or 24.
- 12, 15, 18, 21, 24 words use BIP39 format
- 16 words use Polyseed format`,
		Example: `  seedify ~/.ssh/id_ed25519 --words 12
  seedify ~/.ssh/id_ed25519 --words 15
  seedify ~/.ssh/id_ed25519 --words 16
  seedify ~/.ssh/id_ed25519 --all
  seedify ~/.ssh/id_ed25519 --words 12 --seed-passphrase "my-passphrase"
  seedify ~/.ssh/id_ed25519 --brave
  seedify ~/.ssh/id_ed25519 --all --brave
  cat ~/.ssh/id_ed25519 | seedify --words 18`,
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, args []string) error {
			if err := setLanguage(language); err != nil {
				return err
			}

			var keyPath string
			if len(args) > 0 {
				keyPath = args[0]
			}

			// Handle --all flag
			if all {
				err := generateAllSeedPhrases(keyPath, raw, seedPassphrase, brave)
				if err != nil && strings.Contains(err.Error(), "key is not password-protected") {
					return formatPasswordError(err)
				}
				return err
			}

			// Handle --brave flag: generate 25-word phrase with Brave Sync
			if brave {
				mnemonic, err := generateBraveSyncPhrase(keyPath, seedPassphrase)
				if err != nil {
					if strings.Contains(err.Error(), "key is not password-protected") {
						return formatPasswordError(err)
					}
					return err
				}

				if raw {
					fmt.Println(mnemonic)
					return nil
				}

				if isatty.IsTerminal(os.Stdout.Fd()) {
					b := strings.Builder{}
					w := getWidth(maxWidth)

					b.WriteRune('\n')
					renderBlock(&b, baseStyle, w, "Generated 25-word seed phrase (with Brave Sync):")
					renderBlock(&b, mnemonicStyle, w, mnemonic)
					b.WriteRune('\n')
					renderBlock(&b, baseStyle, w, "Warning: Brave does not officially support using the Sync code as a backup and you should not rely on this continuing to work in the future.")
					b.WriteRune('\n')

					fmt.Println(b.String())
				} else {
					fmt.Println(mnemonic)
				}
				return nil
			}

			// Show warning for 16 words (polyseed format) unless --raw is used
			if wordCount == 16 && !raw {
				_, _ = fmt.Fprintf(os.Stderr, "Warning: 16 words will be in Polyseed format (not BIP39). Use --raw to suppress this message.\n")
			}

			mnemonic, err := generateSeedPhrase(keyPath, nil, wordCount, seedPassphrase, brave)
			if err != nil {
				if strings.Contains(err.Error(), "key is not password-protected") {
					return formatPasswordError(err)
				}
				return err
			}

			if raw {
				fmt.Println(mnemonic)
				return nil
			}
			if isatty.IsTerminal(os.Stdout.Fd()) {
				b := strings.Builder{}
				w := getWidth(maxWidth)

				b.WriteRune('\n')
				formatNote := ""
				if wordCount == 16 {
					formatNote = " (Polyseed format)"
				}
				renderBlock(&b, baseStyle, w, fmt.Sprintf("Generated %d-word seed phrase%s:", wordCount, formatNote))
				renderBlock(&b, mnemonicStyle, w, mnemonic)
				b.WriteRune('\n')

				fmt.Println(b.String())
			} else {
				fmt.Println(mnemonic)
			}
			return nil
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
  seedify brave-sync-25th --date "2024-01-15"
  seedify brave-sync-25th --raw`,
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
				return err
			}

			if raw {
				fmt.Println(word)
				return nil
			}

			if isatty.IsTerminal(os.Stdout.Fd()) {
				b := strings.Builder{}
				w := getWidth(maxWidth)

				b.WriteRune('\n')
				renderBlock(&b, baseStyle, w, "The 25th word for Brave Sync is:")
				renderBlock(&b, mnemonicStyle, w, word)
				b.WriteRune('\n')
				renderBlock(&b, baseStyle, w, "Warning: Brave does not officially support using the Sync code as a backup and you should not rely on this continuing to work in the future.")
				b.WriteRune('\n')

				fmt.Println(b.String())
			} else {
				fmt.Println(word)
			}

			return nil
		},
	}

	dateStr string
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&language, "language", "l", "en", "Language")
	rootCmd.PersistentFlags().BoolVar(&raw, "raw", false, "Print raw seed phrase (words and spaces only)")
	rootCmd.PersistentFlags().IntVarP(&wordCount, "words", "w", 24, "Number of words in the phrase (12, 15, 16, 18, 21, or 24)")
	rootCmd.PersistentFlags().BoolVar(&all, "all", false, "Generate seed phrases for all word counts (12, 15, 16, 18, 21, 24)")
	rootCmd.PersistentFlags().StringVar(&seedPassphrase, "seed-passphrase", "", "Passphrase to combine with SSH key seed for additional entropy")
	rootCmd.PersistentFlags().BoolVar(&brave, "brave", false, "Generate 25-word phrase with Brave Sync (prepends hash of 'brave' to entropy and appends 25th word)")
	rootCmd.AddCommand(manCmd)
	rootCmd.AddCommand(braveSync25thCmd)
	braveSync25thCmd.Flags().StringVar(&dateStr, "date", "", "Get the 25th word for a specific date (format: YYYY-MM-DD)")
	braveSync25thCmd.Flags().BoolVar(&raw, "raw", false, "Print raw word only")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func openFileOrStdin(path string) (*os.File, error) {
	if path == "-" {
		return os.Stdin, nil
	}

	if fi, _ := os.Stdin.Stat(); (fi.Mode() & os.ModeNamedPipe) != 0 {
		return os.Stdin, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("could not open %s: %w", path, err)
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
		return seedify.ToMnemonicWithBraveSync(key, seedPassphrase)
	default:
		return "", fmt.Errorf("unknown key type: %v", key)
	}
}

// generateSeedPhrase generates a seed phrase from an SSH key.
// seedPassphrase is combined with the SSH key seed to add additional entropy.
// brave flag determines if the "brave" hash prefix should be prepended.
func generateSeedPhrase(path string, pass []byte, wordCount int, seedPassphrase string, brave bool) (string, error) {
	// Validate word count
	validCounts := map[int]bool{12: true, 15: true, 16: true, 18: true, 21: true, 24: true}
	if !validCounts[wordCount] {
		return "", fmt.Errorf("invalid word count: %d (must be 12, 15, 16, 18, 21, or 24)", wordCount)
	}

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
	// We need to check this before attempting to parse with a password
	// because if pass is nil, we want to detect unencrypted keys
	if pass == nil {
		isProtected, err := isKeyPasswordProtected(bts)
		if err != nil {
			// If we can't determine, continue with normal parsing flow
		} else if !isProtected {
			// Key is not password-protected - reject it
			return "", fmt.Errorf("key is not password-protected: keys are required to be password-protected")
		}
	}

	key, err := parsePrivateKey(bts, pass)
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
		// Generate mnemonic with the specified word count and seed passphrase
		return seedify.ToMnemonicWithLength(key, wordCount, seedPassphrase, brave)
	default:
		return "", fmt.Errorf("unknown key type: %v", key)
	}
}

// generateAllSeedPhrases generates seed phrases for all word counts and formats them nicely.
// seedPassphrase is combined with the SSH key seed to add additional entropy.
// If brave is true, also generates a 25-word phrase with Brave Sync.
func generateAllSeedPhrases(path string, rawOutput bool, seedPassphrase string, brave bool) error {
	return generateAllSeedPhrasesWithPass(path, rawOutput, seedPassphrase, nil, brave)
}

// generateAllSeedPhrasesWithPass is the internal implementation that handles password-protected keys.
// If brave is true, also generates a 25-word phrase with Brave Sync.
func generateAllSeedPhrasesWithPass(path string, rawOutput bool, seedPassphrase string, pass []byte, brave bool) error {
	// All valid word counts in order
	wordCounts := []int{12, 15, 16, 18, 21, 24}

	// Parse the key once
	f, err := openFileOrStdin(path)
	if err != nil {
		return fmt.Errorf("could not read key: %w", err)
	}
	defer f.Close() //nolint:errcheck
	bts, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("could not read key: %w", err)
	}

	// Check if key is password-protected (required for this command)
	// We need to check this before attempting to parse with a password
	// because if pass is nil, we want to detect unencrypted keys
	if pass == nil {
		isProtected, err := isKeyPasswordProtected(bts)
		if err != nil {
			// If we can't determine, continue with normal parsing flow
		} else if !isProtected {
			// Key is not password-protected - reject it
			return fmt.Errorf("key is not password-protected: keys are required to be password-protected")
		}
	}

	key, err := parsePrivateKey(bts, pass)
	if err != nil && isPasswordError(err) {
		// Key requires a password - ask for it and parse again with the same bytes
		pass, err := askKeyPassphrase(path)
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

	// Generate all mnemonics
	mnemonics := make(map[int]string)
	for _, count := range wordCounts {
		mnemonic, err := seedify.ToMnemonicWithLength(ed25519Key, count, seedPassphrase, false)
		if err != nil {
			return fmt.Errorf("could not generate %d-word mnemonic: %w", count, err)
		}
		mnemonics[count] = mnemonic
	}

	// Generate Brave Sync 25-word phrase if requested
	var braveMnemonic string
	if brave {
		var err error
		braveMnemonic, err = seedify.ToMnemonicWithBraveSync(ed25519Key, seedPassphrase)
		if err != nil {
			return fmt.Errorf("could not generate Brave Sync mnemonic: %w", err)
		}
	}

	// Output formatting
	if rawOutput {
		// Raw output: just print all mnemonics separated by newlines
		for i, count := range wordCounts {
			fmt.Printf("%d words:\n", count)
			fmt.Println(mnemonics[count])
			// Add blank line between each category (except after the last one)
			if i < len(wordCounts)-1 {
				fmt.Println()
			}
		}
		// Add Brave Sync phrase if requested
		if brave {
			if len(wordCounts) > 0 {
				fmt.Println()
			}
			fmt.Println("25 words (Brave Sync):")
			fmt.Println(braveMnemonic)
		}
		return nil
	}

		if isatty.IsTerminal(os.Stdout.Fd()) {
		// Formatted output for terminal
		b := strings.Builder{}
		w := getWidth(maxWidth)

		b.WriteRune('\n')
		renderBlock(&b, baseStyle, w, "Generated seed phrases for all formats:")
		b.WriteRune('\n')

		for _, count := range wordCounts {
			formatNote := ""
			if count == 16 {
				formatNote = " (Polyseed format)"
			} else {
				formatNote = " (BIP39 format)"
			}

			header := fmt.Sprintf("%d words%s:", count, formatNote)
			renderBlock(&b, baseStyle, w, header)
			renderBlock(&b, mnemonicStyle, w, mnemonics[count])
			b.WriteRune('\n')
		}

		// Add Brave Sync phrase if requested (below the 24 words section)
		if brave {
			b.WriteRune('\n')
			renderBlock(&b, baseStyle, w, "25 words (Brave Sync):")
			renderBlock(&b, mnemonicStyle, w, braveMnemonic)
			b.WriteRune('\n')
			renderBlock(&b, baseStyle, w, "Warning: Brave does not officially support using the Sync code as a backup and you should not rely on this continuing to work in the future.")
			b.WriteRune('\n')
		}

		fmt.Println(b.String())
	} else {
		// Non-terminal output: structured format
		for _, count := range wordCounts {
			formatNote := ""
			if count == 16 {
				formatNote = " (Polyseed)"
			} else {
				formatNote = " (BIP39)"
			}
			fmt.Printf("%d words%s: %s\n", count, formatNote, mnemonics[count])
		}
		// Add Brave Sync phrase if requested
		if brave {
			fmt.Printf("25 words (Brave Sync): %s\n", braveMnemonic)
		}
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

func askKeyPassphrase(path string) ([]byte, error) {
	defer fmt.Fprintf(os.Stderr, "\n")
	return readPassword(fmt.Sprintf("Enter the passphrase to unlock %q: ", path))
}

