// Copyright (c) 2025-2026 complex (complex@ft.hn)
// See LICENSE for licensing information

// Package seedify provides functions to create seed phrases deterministically
// from an SSH key. This package does not provide functionality to recover
// the original SSH key from the seed phrase.
//
// The purpose of seedify is to generate seed phrases of various lengths
// (12, 15, 16, 18, 21, or 24 words) from an ed25519 private key. These phrases
// can be used for various purposes.
package seedify

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"time"

	"filippo.io/edwards25519"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/chekist32/go-monero/utils"
	polyseed "github.com/complex-gh/polyseed_go"
	"github.com/mr-tron/base58"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip06"
	"github.com/nbd-wtf/go-nostr/nip19"
	hdwallet "github.com/stephenlacy/go-ethereum-hdwallet"
	"github.com/tyler-smith/go-bip39"
	"github.com/tyler-smith/go-bip39/wordlists"
	"golang.org/x/crypto/blake2b"
)

// Constants for mnemonic generation.
const (
	// wordCountBytesSize is the size in bytes for encoding word count (uint16).
	wordCountBytesSize = 2
	// polyseedWordCount is the word count for polyseed format mnemonics.
	polyseedWordCount = 16
	// bip39MaxWordCount is the maximum word count for BIP39 mnemonics.
	bip39MaxWordCount = 24
	// msPerSecond is the number of milliseconds in one second.
	msPerSecond = 1000
)

// entropySizeMap maps word count to entropy size in bytes for BIP39.
//
//nolint:mnd
var entropySizeMap = map[int]int{
	12: 16, // 128 bits
	15: 20, // 160 bits
	18: 24, // 192 bits
	21: 28, // 224 bits
	24: 32, // 256 bits
}

// combineSeedPassphrase combines a seed passphrase with the SSH key seed to create
// combined entropy. The passphrase is hashed with SHA256 to produce 32 bytes,
// which are then XORed with the key seed to combine the entropy deterministically.
func combineSeedPassphrase(keySeed []byte, seedPassphrase string) []byte {
	// Hash the passphrase to get 32 bytes of entropy
	passphraseHash := sha256.Sum256([]byte(seedPassphrase))

	// Combine by XORing the hashed passphrase with the key seed
	combined := make([]byte, len(keySeed))
	for i := range keySeed {
		combined[i] = keySeed[i] ^ passphraseHash[i]
	}

	return combined
}

// ToMnemonicWithLength takes an ed25519 private key and returns a mnemonic
// phrase of the specified word count. This is an auxiliary utility function.
// The generated phrases cannot be used with FromMnemonic to recover the
// original key if the word count is less than 24.
//
// If seedPassphrase is provided (non-empty), it will be combined with the
// SSH key seed to add additional entropy: ENTROPY(seed-passphrase) + ENTROPY(ssh-key).
//
// The word count is prepended to the entropy to ensure different word counts
// generate completely different words, not just truncated versions of the same phrase.
// Exception: For 24 words (when brave is false), the raw seed is used directly
// without prepending word count or hashing.
//
// If brave is true, the hash of "brave" is prepended to the entropy (similar to
// word count) to generate a different set of words.
//
// Valid word counts are: 12, 15, 16, 18, 21, or 24.
// The entropy size is determined by the word count:
//   - 12 words = 128 bits (16 bytes) - BIP39
//   - 15 words = 160 bits (20 bytes) - BIP39
//   - 16 words = 150 bits (19 bytes) - Polyseed format
//   - 18 words = 192 bits (24 bytes) - BIP39
//   - 21 words = 224 bits (28 bytes) - BIP39
//   - 24 words = 256 bits (32 bytes) - BIP39
func ToMnemonicWithLength(key *ed25519.PrivateKey, wordCount int, seedPassphrase string, brave bool) (string, error) {
	// Delegate to ToMnemonicWithPrefix with "brave" as the prefix when brave is true
	var prefix string
	if brave {
		prefix = "brave"
	}
	return ToMnemonicWithPrefix(key, wordCount, seedPassphrase, prefix)
}

// ToMnemonicWithPrefix takes an ed25519 private key and returns a mnemonic
// phrase of the specified word count. It is a generalization of ToMnemonicWithLength
// that accepts an arbitrary prefix string instead of a boolean brave flag.
//
// If prefix is non-empty, the hash of the prefix string is prepended to the entropy
// (similar to how the word count is prepended) to generate a completely different
// set of words. This allows generating distinct seed phrases for different
// applications (e.g., "brave" for Brave Sync, "wallet" for Brave Wallet).
//
// If seedPassphrase is provided (non-empty), it will be combined with the
// SSH key seed to add additional entropy: ENTROPY(seed-passphrase) + ENTROPY(ssh-key).
//
// The word count is prepended to the entropy to ensure different word counts
// generate completely different words, not just truncated versions of the same phrase.
// Exception: For 24 words (when prefix is empty), the raw seed is used directly
// without prepending word count or hashing.
//
// Valid word counts are: 12, 15, 16, 18, 21, or 24.
// The entropy size is determined by the word count:
//   - 12 words = 128 bits (16 bytes) - BIP39
//   - 15 words = 160 bits (20 bytes) - BIP39
//   - 16 words = 150 bits (19 bytes) - Polyseed format
//   - 18 words = 192 bits (24 bytes) - BIP39
//   - 21 words = 224 bits (28 bytes) - BIP39
//   - 24 words = 256 bits (32 bytes) - BIP39
func ToMnemonicWithPrefix(key *ed25519.PrivateKey, wordCount int, seedPassphrase string, prefix string) (string, error) {
	// Get the full seed (32 bytes)
	fullSeed := key.Seed()

	// Combine with seed passphrase if provided
	var combinedSeed []byte
	if seedPassphrase != "" {
		combinedSeed = combineSeedPassphrase(fullSeed, seedPassphrase)
	} else {
		combinedSeed = make([]byte, len(fullSeed))
		copy(combinedSeed, fullSeed)
	}

	// Special handling for 24 words with no prefix: use raw seed directly
	// Skip word count prefix and hashing to ensure compatibility
	if wordCount == 24 && prefix == "" {
		// Use the combined seed directly as entropy (32 bytes for 24 words)
		words, err := bip39.NewMnemonic(combinedSeed)
		if err != nil {
			return "", fmt.Errorf("could not create a mnemonic set of words: %w", err)
		}
		return words, nil
	}

	// Prepend word count to the seed to ensure different word counts generate
	// completely different words. We encode the word count as a uint16 (wordCountBytesSize bytes)
	// to ensure it's properly incorporated into the entropy.
	// Valid word counts are 12, 15, 16, 18, 21, 24 - all within uint16 range.
	wordCountBytes := make([]byte, wordCountBytesSize)
	binary.BigEndian.PutUint16(wordCountBytes, uint16(wordCount)) //nolint:gosec

	// If a prefix is provided, prepend its hash (similar to word count)
	var prefixBytes []byte
	if prefix != "" {
		// Hash the prefix string and take the first 2 bytes (same size as word count)
		prefixHash := sha256.Sum256([]byte(prefix))
		hashPrefix := prefixHash[:2]
		// Combine hash prefix with word count prefix
		prefixBytes = make([]byte, len(hashPrefix)+len(wordCountBytes))
		copy(prefixBytes, hashPrefix)
		copy(prefixBytes[len(hashPrefix):], wordCountBytes)
	} else {
		prefixBytes = wordCountBytes
	}

	// Combine prefix with the seed
	prefixedSeed := make([]byte, len(prefixBytes)+len(combinedSeed))
	copy(prefixedSeed, prefixBytes)
	copy(prefixedSeed[len(prefixBytes):], combinedSeed)

	// Special handling for 16 words - use polyseed format
	if wordCount == polyseedWordCount {
		// Hash the prefixed seed to get exactly 19 bytes (150 bits) for polyseed
		// We use SHA256 and take the first 19 bytes
		hash := sha256.Sum256(prefixedSeed)
		polyseedBytes := hash[:19]

		seed, err := polyseed.CreateFromBytes(polyseedBytes, 0)
		if err != nil {
			return "", fmt.Errorf("could not create polyseed: %w", err)
		}
		defer seed.Free()

		// Get English language (index 0) for encoding.
		// Note: Other languages may be supported in future versions based on user preference.
		lang := polyseed.GetLang(0)
		if lang == nil {
			return "", fmt.Errorf("could not get polyseed language")
		}

		// Encode to mnemonic using Monero coin (default)
		mnemonic := seed.Encode(lang, polyseed.CoinMonero)

		return mnemonic, nil
	}

	// Look up entropy size for the requested word count
	entropySize, ok := entropySizeMap[wordCount]
	if !ok {
		return "", fmt.Errorf("invalid word count: %d (must be 12, 15, 16, 18, 21, or 24)", wordCount)
	}

	// Hash the prefixed seed to get exactly the required entropy size
	// This ensures different word counts produce completely different words
	hash := sha256.Sum256(prefixedSeed)
	entropy := hash[:entropySize]

	// Generate the mnemonic from the hashed entropy
	words, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("could not create a mnemonic set of words: %w", err)
	}

	return words, nil
}

// BraveSync25thWord returns the 25th word for Brave Sync based on the current date.
// The 25th word changes daily and is calculated from the epoch date
// "Tue, 10 May 2022 00:00:00 GMT". The number of days since the epoch is used
// as an index into the BIP39 English word list.
//
// This function replicates the logic from the JavaScript implementation at
// https://alexeybarabash.github.io/25th-brave-sync-word/
//
// Returns an error if the current date is before the epoch date or if the
// calculated index is out of bounds for the BIP39 word list.
func BraveSync25thWord() (string, error) {
	return BraveSync25thWordForDate(time.Now().UTC())
}

// BraveSync25thWordForDate returns the 25th word for Brave Sync for a specific date.
// This allows you to get the 25th word for any date, not just today.
//
// The date parameter should be in UTC. The number of days since the epoch
// "Tue, 10 May 2022 00:00:00 GMT" is used as an index into the BIP39 English word list.
//
// Returns an error if the provided date is before the epoch date or if the
// calculated index is out of bounds for the BIP39 word list.
func BraveSync25thWordForDate(date time.Time) (string, error) {
	// Parse the epoch date: "Tue, 10 May 2022 00:00:00 GMT"
	// Using RFC1123 format which matches the JavaScript Date string format
	epochDate, err := time.Parse(time.RFC1123, "Tue, 10 May 2022 00:00:00 GMT")
	if err != nil {
		return "", fmt.Errorf("could not parse epoch date: %w", err)
	}

	// Ensure we're working in UTC
	epochDate = epochDate.UTC()
	dateUTC := date.UTC()

	// Calculate the difference in milliseconds, then convert to days
	deltaInMsec := dateUTC.Sub(epochDate).Milliseconds()
	deltaInDays := float64(deltaInMsec) / (24 * 60 * 60 * msPerSecond)
	// Round to nearest integer to match JavaScript Math.round() behavior
	deltaInDaysRounded := int64(math.Round(deltaInDays))

	// Check if date is before epoch
	if deltaInDaysRounded < 0 {
		return "", fmt.Errorf("date %s is before the epoch date %s", dateUTC.Format(time.RFC1123), epochDate.Format(time.RFC1123))
	}

	// Get the BIP39 English word list
	wordList := wordlists.English
	if wordList == nil {
		return "", fmt.Errorf("BIP39 English word list is not available")
	}

	// Check bounds - BIP39 word list has 2048 words (indices 0-2047)
	if deltaInDaysRounded >= int64(len(wordList)) {
		return "", fmt.Errorf("calculated index %d is out of bounds for BIP39 word list (max index: %d)", deltaInDaysRounded, len(wordList)-1)
	}

	// Return the word at the calculated index
	return wordList[deltaInDaysRounded], nil
}

// ToMnemonicWithBraveSync generates a 24-word mnemonic with the "brave" prefix
// and appends the 25th word from Brave Sync. This creates a 25-word phrase
// suitable for use with Brave Sync.
//
// The function generates 24 words using the same logic as ToMnemonicWithLength
// with the brave flag set, then appends the current day's 25th word from Brave Sync.
func ToMnemonicWithBraveSync(key *ed25519.PrivateKey, seedPassphrase string) (string, error) {
	// Generate 24 words with brave flag set
	mnemonic24, err := ToMnemonicWithLength(key, bip39MaxWordCount, seedPassphrase, true)
	if err != nil {
		return "", fmt.Errorf("could not generate 24-word mnemonic: %w", err)
	}

	// Get the 25th word for today
	word25, err := BraveSync25thWord()
	if err != nil {
		return "", fmt.Errorf("could not get 25th word: %w", err)
	}

	// Append the 25th word to the 24-word phrase
	return fmt.Sprintf("%s %s", mnemonic24, word25), nil
}

// NostrKeys contains all Nostr key formats derived from a mnemonic.
type NostrKeys struct {
	// Npub is the public key in bech32 format (starts with "npub1")
	Npub string
	// Nsec is the private key in bech32 format (starts with "nsec1")
	Nsec string
	// PubKeyHex is the raw public key in hexadecimal format (64 characters)
	PubKeyHex string
	// PrivKeyHex is the raw private key in hexadecimal format (64 characters)
	PrivKeyHex string
}

// DeriveNostrKeysWithHex derives Nostr keys from a BIP39 mnemonic phrase.
// Returns keys in both bech32 (npub/nsec) and hexadecimal formats.
// The function follows NIP-06 standard: it converts the mnemonic to a BIP39 seed,
// then uses BIP32 hierarchical derivation with path m/44'/1237'/0'/0/0 to derive
// the Nostr private key.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - NostrKeys: Contains npub, nsec, pubKeyHex, and privKeyHex
//   - error: Any error that occurred during derivation
func DeriveNostrKeysWithHex(mnemonic string, bip39Passphrase string) (*NostrKeys, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Derive private key using NIP-06 standard BIP32 path: m/44'/1237'/0'/0/0
	privateKeyHex, err := nip06.PrivateKeyFromSeed(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to derive private key from seed: %w", err)
	}

	// Derive public key from private key
	publicKeyHex, err := nostr.GetPublicKey(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	// Encode keys to npub/nsec format using nip19 bech32 encoding
	npub, err := nip19.EncodePublicKey(publicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to encode public key: %w", err)
	}

	nsec, err := nip19.EncodePrivateKey(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to encode private key: %w", err)
	}

	return &NostrKeys{
		Npub:       npub,
		Nsec:       nsec,
		PubKeyHex:  publicKeyHex,
		PrivKeyHex: privateKeyHex,
	}, nil
}

// DeriveNostrKeys derives Nostr keys (npub/nsec) from a BIP39 mnemonic phrase.
// The function follows NIP-06 standard: it converts the mnemonic to a BIP39 seed,
// then uses BIP32 hierarchical derivation with path m/44'/1237'/0'/0/0 to derive
// the Nostr private key. The keys are encoded to npub/nsec format using bech32.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - npub: The Nostr public key in bech32 format (starts with "npub1")
//   - nsec: The Nostr private key in bech32 format (starts with "nsec1")
//   - error: Any error that occurred during derivation
func DeriveNostrKeys(mnemonic string, bip39Passphrase string) (npub string, nsec string, err error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return "", "", fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Derive private key using NIP-06 standard BIP32 path: m/44'/1237'/0'/0/0
	privateKeyHex, err := nip06.PrivateKeyFromSeed(seed)
	if err != nil {
		return "", "", fmt.Errorf("failed to derive private key from seed: %w", err)
	}

	// Derive public key from private key
	publicKeyHex, err := nostr.GetPublicKey(privateKeyHex)
	if err != nil {
		return "", "", fmt.Errorf("failed to derive public key: %w", err)
	}

	// Encode keys to npub/nsec format using nip19 bech32 encoding
	npub, err = nip19.EncodePublicKey(publicKeyHex)
	if err != nil {
		return "", "", fmt.Errorf("failed to encode public key: %w", err)
	}

	nsec, err = nip19.EncodePrivateKey(privateKeyHex)
	if err != nil {
		return "", "", fmt.Errorf("failed to encode private key: %w", err)
	}

	return npub, nsec, nil
}

// DeriveNostrKeysFromEd25519 derives Nostr keys (npub/nsec) directly from an Ed25519 private key.
// This function is used to derive Nostr keys from SSH keys without going through seed phrases.
//
// Parameters:
//   - key: An Ed25519 private key (e.g., from an SSH key)
//
// Returns:
//   - npub: The Nostr public key in bech32 format (starts with "npub1")
//   - nsec: The Nostr private key in bech32 format (starts with "nsec1")
//   - error: Any error that occurred during derivation
func DeriveNostrKeysFromEd25519(key *ed25519.PrivateKey) (npub string, nsec string, err error) {
	// Get the public key from the private key
	publicKey := (*key).Public().(ed25519.PublicKey)

	// Convert keys to hex strings (Nostr uses hex-encoded keys)
	// Use Seed() to get the 32-byte private key seed, not the full 64-byte key
	privateKeyHex := hex.EncodeToString((*key).Seed())
	publicKeyHex := hex.EncodeToString(publicKey)

	// Encode keys to npub/nsec format using nip19 bech32 encoding
	npub, err = nip19.EncodePublicKey(publicKeyHex)
	if err != nil {
		return "", "", fmt.Errorf("failed to encode public key: %w", err)
	}

	nsec, err = nip19.EncodePrivateKey(privateKeyHex)
	if err != nil {
		return "", "", fmt.Errorf("failed to encode private key: %w", err)
	}

	return npub, nsec, nil
}

// DeriveBitcoinAddress derives a Bitcoin address from a BIP39 mnemonic phrase.
// The function follows BIP44 standard with derivation path m/44'/0'/0'/0/0.
// It returns a P2PKH address (starts with "1") for Bitcoin mainnet.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - address: The Bitcoin P2PKH address
//   - error: Any error that occurred during derivation
func DeriveBitcoinAddress(mnemonic string, bip39Passphrase string) (string, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return "", fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive BIP44 path: m/44'/0'/0'/0/0
	// 44' = purpose (BIP44)
	// 0' = coin type (Bitcoin)
	// 0' = account
	// 0 = change (external)
	// 0 = address index
	purpose, err := masterKey.Derive(hdkeychain.HardenedKeyStart + 44) //nolint:mnd
	if err != nil {
		return "", fmt.Errorf("failed to derive purpose: %w", err)
	}

	coinType, err := purpose.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return "", fmt.Errorf("failed to derive coin type: %w", err)
	}

	account, err := coinType.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return "", fmt.Errorf("failed to derive account: %w", err)
	}

	change, err := account.Derive(0)
	if err != nil {
		return "", fmt.Errorf("failed to derive change: %w", err)
	}

	addressIndex, err := change.Derive(0)
	if err != nil {
		return "", fmt.Errorf("failed to derive address index: %w", err)
	}

	// Get the public key and create P2PKH address
	pubKey, err := addressIndex.ECPubKey()
	if err != nil {
		return "", fmt.Errorf("failed to get public key: %w", err)
	}

	// Create P2PKH address (starts with "1")
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	addr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("failed to create address: %w", err)
	}

	return addr.EncodeAddress(), nil
}

// DeriveBitcoinAddressSegwit derives a P2SH-P2WPKH (Nested SegWit) Bitcoin address.
// The function follows BIP49 standard with derivation path m/49'/0'/0'/0/0.
// It returns a P2SH-wrapped SegWit address (starts with "3") for Bitcoin mainnet.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - address: The Bitcoin P2SH-P2WPKH address (starts with "3")
//   - error: Any error that occurred during derivation
func DeriveBitcoinAddressSegwit(mnemonic string, bip39Passphrase string) (string, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return "", fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive BIP49 path: m/49'/0'/0'/0/0
	// 49' = purpose (BIP49 - P2SH-P2WPKH)
	// 0' = coin type (Bitcoin)
	// 0' = account
	// 0 = change (external)
	// 0 = address index
	purpose, err := masterKey.Derive(hdkeychain.HardenedKeyStart + 49) //nolint:mnd
	if err != nil {
		return "", fmt.Errorf("failed to derive purpose: %w", err)
	}

	coinType, err := purpose.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return "", fmt.Errorf("failed to derive coin type: %w", err)
	}

	account, err := coinType.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return "", fmt.Errorf("failed to derive account: %w", err)
	}

	change, err := account.Derive(0)
	if err != nil {
		return "", fmt.Errorf("failed to derive change: %w", err)
	}

	addressIndex, err := change.Derive(0)
	if err != nil {
		return "", fmt.Errorf("failed to derive address index: %w", err)
	}

	// Get the public key
	pubKey, err := addressIndex.ECPubKey()
	if err != nil {
		return "", fmt.Errorf("failed to get public key: %w", err)
	}

	// Create P2WPKH (witness) address first
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	witnessAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("failed to create witness address: %w", err)
	}

	// Wrap in P2SH to create P2SH-P2WPKH address (starts with "3")
	script, err := txscript.PayToAddrScript(witnessAddr)
	if err != nil {
		return "", fmt.Errorf("failed to create script: %w", err)
	}

	addr, err := btcutil.NewAddressScriptHash(script, &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("failed to create P2SH address: %w", err)
	}

	return addr.EncodeAddress(), nil
}

// DeriveBitcoinAddressNativeSegwit derives a P2WPKH (Native SegWit) Bitcoin address.
// The function follows BIP84 standard with derivation path m/84'/0'/0'/0/0.
// It returns a Bech32 address (starts with "bc1q") for Bitcoin mainnet.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - address: The Bitcoin P2WPKH address (starts with "bc1q")
//   - error: Any error that occurred during derivation
func DeriveBitcoinAddressNativeSegwit(mnemonic string, bip39Passphrase string) (string, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return "", fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive BIP84 path: m/84'/0'/0'/0/0
	// 84' = purpose (BIP84 - P2WPKH native SegWit)
	// 0' = coin type (Bitcoin)
	// 0' = account
	// 0 = change (external)
	// 0 = address index
	purpose, err := masterKey.Derive(hdkeychain.HardenedKeyStart + 84) //nolint:mnd
	if err != nil {
		return "", fmt.Errorf("failed to derive purpose: %w", err)
	}

	coinType, err := purpose.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return "", fmt.Errorf("failed to derive coin type: %w", err)
	}

	account, err := coinType.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return "", fmt.Errorf("failed to derive account: %w", err)
	}

	change, err := account.Derive(0)
	if err != nil {
		return "", fmt.Errorf("failed to derive change: %w", err)
	}

	addressIndex, err := change.Derive(0)
	if err != nil {
		return "", fmt.Errorf("failed to derive address index: %w", err)
	}

	// Get the public key and create P2WPKH address
	pubKey, err := addressIndex.ECPubKey()
	if err != nil {
		return "", fmt.Errorf("failed to get public key: %w", err)
	}

	// Create P2WPKH address (starts with "bc1q")
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	addr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("failed to create address: %w", err)
	}

	return addr.EncodeAddress(), nil
}

// DeriveBitcoinAddressTaproot derives a P2TR (Taproot) Bitcoin address.
// The function follows BIP86 standard with derivation path m/86'/0'/0'/0/0.
// It returns a Bech32m address (starts with "bc1p") for Bitcoin mainnet.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - address: The Bitcoin P2TR address (starts with "bc1p")
//   - error: Any error that occurred during derivation
func DeriveBitcoinAddressTaproot(mnemonic string, bip39Passphrase string) (string, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return "", fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive BIP86 path: m/86'/0'/0'/0/0
	// 86' = purpose (BIP86 - P2TR Taproot)
	// 0' = coin type (Bitcoin)
	// 0' = account
	// 0 = change (external)
	// 0 = address index
	purpose, err := masterKey.Derive(hdkeychain.HardenedKeyStart + 86) //nolint:mnd
	if err != nil {
		return "", fmt.Errorf("failed to derive purpose: %w", err)
	}

	coinType, err := purpose.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return "", fmt.Errorf("failed to derive coin type: %w", err)
	}

	account, err := coinType.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return "", fmt.Errorf("failed to derive account: %w", err)
	}

	change, err := account.Derive(0)
	if err != nil {
		return "", fmt.Errorf("failed to derive change: %w", err)
	}

	addressIndex, err := change.Derive(0)
	if err != nil {
		return "", fmt.Errorf("failed to derive address index: %w", err)
	}

	// Get the public key for Taproot
	pubKey, err := addressIndex.ECPubKey()
	if err != nil {
		return "", fmt.Errorf("failed to get public key: %w", err)
	}

	// For Taproot, we use the x-only public key (32 bytes)
	// The internal key is tweaked with an empty merkle root for key-path spending
	internalKey := pubKey

	// Compute the taproot tweak: t = tagged_hash("TapTweak", pubkey)
	// Then compute the output key: Q = P + t*G
	taprootKey := txscript.ComputeTaprootKeyNoScript(internalKey)

	// Create P2TR address (starts with "bc1p")
	addr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(taprootKey), &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("failed to create taproot address: %w", err)
	}

	return addr.EncodeAddress(), nil
}

// DeriveBitcoinTaprootKeys derives a Bitcoin Taproot P2TR address and its WIF private key.
// The function follows BIP86 standard with derivation path m/86'/0'/0'/0/0.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - BitcoinKeys: The address and WIF-encoded private key
//   - error: Any error that occurred during derivation
func DeriveBitcoinTaprootKeys(mnemonic string, bip39Passphrase string) (*BitcoinKeys, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive BIP86 path: m/86'/0'/0'/0/0
	path := []uint32{
		hdkeychain.HardenedKeyStart + 86, // purpose (BIP86)
		hdkeychain.HardenedKeyStart + 0,  // coin type (Bitcoin)
		hdkeychain.HardenedKeyStart + 0,  // account
		0,                                // change (external)
		0,                                // address index
	}
	addressKey, err := deriveBIP32Path(masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("failed to derive address key: %w", err)
	}

	// Get the public key for Taproot
	pubKey, err := addressKey.ECPubKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// For Taproot, we use the x-only public key (32 bytes)
	// The internal key is tweaked with an empty merkle root for key-path spending
	taprootKey := txscript.ComputeTaprootKeyNoScript(pubKey)

	// Create P2TR address (starts with "bc1p")
	addr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(taprootKey), &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create taproot address: %w", err)
	}

	// Get the private key in WIF format
	privKey, err := addressKey.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}
	wif, err := btcutil.NewWIF(privKey, &chaincfg.MainNetParams, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create WIF: %w", err)
	}

	return &BitcoinKeys{
		Address:    addr.EncodeAddress(),
		PrivateWIF: wif.String(),
	}, nil
}

// DeriveBitcoinTaprootExtendedKeys derives the extended public and private keys for BIP86 Taproot.
// Returns xpub and xprv at the account level (m/86'/0'/0').
// Note: There is no widely adopted SLIP-132 prefix for taproot, so standard xpub/xprv is used.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - BitcoinExtendedKeys: The xpub and xprv at account level
//   - error: Any error that occurred during derivation
func DeriveBitcoinTaprootExtendedKeys(mnemonic string, bip39Passphrase string) (*BitcoinExtendedKeys, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive to account level: m/86'/0'/0'
	path := []uint32{
		hdkeychain.HardenedKeyStart + 86, // purpose (BIP86)
		hdkeychain.HardenedKeyStart + 0,  // coin type (Bitcoin)
		hdkeychain.HardenedKeyStart + 0,  // account
	}
	accountKey, err := deriveBIP32Path(masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("failed to derive account key: %w", err)
	}

	// Get the public key version (neuter removes the private key)
	accountPubKey, err := accountKey.Neuter()
	if err != nil {
		return nil, fmt.Errorf("failed to neuter key: %w", err)
	}

	// Use standard xpub/xprv format (no SLIP-132 prefix for taproot)
	return &BitcoinExtendedKeys{
		ExtendedPublicKey:  accountPubKey.String(),
		ExtendedPrivateKey: accountKey.String(),
	}, nil
}

// DeriveEthereumAddress derives an Ethereum address from a BIP39 mnemonic phrase.
// The function follows BIP44 standard with derivation path m/44'/60'/0'/0/0.
// It returns a checksummed Ethereum address (starts with "0x").
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - address: The Ethereum address with 0x prefix
//   - error: Any error that occurred during derivation
func DeriveEthereumAddress(mnemonic string, bip39Passphrase string) (string, error) {
	// Create HD wallet from mnemonic with optional passphrase
	var wallet *hdwallet.Wallet
	var err error

	if bip39Passphrase != "" {
		// Use seed directly when passphrase is provided
		seed, seedErr := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
		if seedErr != nil {
			return "", fmt.Errorf("invalid mnemonic: %w", seedErr)
		}
		wallet, err = hdwallet.NewFromSeed(seed)
	} else {
		wallet, err = hdwallet.NewFromMnemonic(mnemonic)
	}
	if err != nil {
		return "", fmt.Errorf("failed to create wallet from mnemonic: %w", err)
	}

	// Derive BIP44 path: m/44'/60'/0'/0/0
	// 44' = purpose (BIP44)
	// 60' = coin type (Ethereum)
	// 0' = account
	// 0 = change (external)
	// 0 = address index
	path := hdwallet.MustParseDerivationPath("m/44'/60'/0'/0/0")
	account, err := wallet.Derive(path, false)
	if err != nil {
		return "", fmt.Errorf("failed to derive account: %w", err)
	}

	return account.Address.Hex(), nil
}

// DeriveTronAddress derives a Tron address from a BIP39 mnemonic phrase.
// The function follows BIP44 standard with derivation path m/44'/195'/0'/0/0.
// Tron uses the same secp256k1 key derivation and Keccak256 address computation
// as Ethereum, but encodes the address using Base58Check with a 0x41 prefix
// instead of hex with a 0x prefix. The resulting address starts with "T".
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - address: The Tron address (Base58Check-encoded, starts with "T")
//   - error: Any error that occurred during derivation
func DeriveTronAddress(mnemonic string, bip39Passphrase string) (string, error) {
	// Create HD wallet from mnemonic with optional passphrase
	var wallet *hdwallet.Wallet
	var err error

	if bip39Passphrase != "" {
		// Use seed directly when passphrase is provided
		seed, seedErr := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
		if seedErr != nil {
			return "", fmt.Errorf("invalid mnemonic: %w", seedErr)
		}
		wallet, err = hdwallet.NewFromSeed(seed)
	} else {
		wallet, err = hdwallet.NewFromMnemonic(mnemonic)
	}
	if err != nil {
		return "", fmt.Errorf("failed to create wallet from mnemonic: %w", err)
	}

	// Derive BIP44 path: m/44'/195'/0'/0/0
	// 44' = purpose (BIP44)
	// 195' = coin type (Tron)
	// 0' = account
	// 0 = change (external)
	// 0 = address index
	path := hdwallet.MustParseDerivationPath("m/44'/195'/0'/0/0")
	account, err := wallet.Derive(path, false)
	if err != nil {
		return "", fmt.Errorf("failed to derive account: %w", err)
	}

	// The hdwallet library computes the Ethereum-style 20-byte address
	// (last 20 bytes of Keccak256 hash of the uncompressed public key).
	// Tron uses the same address bytes, just with a different encoding.
	addrBytes := account.Address.Bytes()

	// Encode as Tron address: Base58Check(0x41 || address_bytes)
	// 0x41 is the Tron mainnet address prefix
	return encodeTronAddress(addrBytes), nil
}

// encodeTronAddress encodes a 20-byte address as a Tron Base58Check address.
// The encoding format is: Base58(0x41 || address || checksum)
// where checksum = SHA256(SHA256(0x41 || address))[:4].
func encodeTronAddress(addrBytes []byte) string {
	// Prepend Tron mainnet prefix (0x41)
	payload := make([]byte, 0, 25)  //nolint:mnd // 1 prefix + 20 address + 4 checksum
	payload = append(payload, 0x41) //nolint:mnd // Tron mainnet address prefix
	payload = append(payload, addrBytes...)

	// Calculate checksum: first 4 bytes of double SHA256
	firstHash := sha256.Sum256(payload)
	secondHash := sha256.Sum256(firstHash[:])
	checksum := secondHash[:4]

	// Append checksum and Base58 encode
	payload = append(payload, checksum...)

	return base58.Encode(payload)
}

// DeriveSolanaAddress derives a Solana address from a BIP39 mnemonic phrase.
// The function follows SLIP-0010/BIP44 standard with derivation path m/44'/501'/0'/0'.
// Solana uses Ed25519 keys, so all path components are hardened.
// It returns a Base58-encoded public key as the Solana address.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - address: The Solana address (Base58-encoded public key)
//   - error: Any error that occurred during derivation
func DeriveSolanaAddress(mnemonic string, bip39Passphrase string) (string, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return "", fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Derive using SLIP-0010 for Ed25519
	// Path: m/44'/501'/0'/0' (all hardened for Ed25519)
	key := deriveEd25519Key(seed, []uint32{44, 501, 0, 0})

	// Generate Ed25519 public key from the derived private key
	privateKey := ed25519.NewKeyFromSeed(key)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	// Solana address is the Base58-encoded public key
	return base58.Encode(publicKey), nil
}

// deriveEd25519Key derives an Ed25519 private key from a seed using SLIP-0010.
// This implements hierarchical deterministic key derivation for Ed25519 curves.
// All derivation indices are treated as hardened (as required by Ed25519).
//
// Parameters:
//   - seed: The BIP39 seed (64 bytes)
//   - path: The derivation path indices (e.g., [44, 501, 0, 0] for m/44'/501'/0'/0')
//
// Returns:
//   - key: The derived 32-byte Ed25519 private key seed
func deriveEd25519Key(seed []byte, path []uint32) []byte {
	// SLIP-0010: Use "ed25519 seed" as the HMAC key for master key generation
	hmacKey := []byte("ed25519 seed")

	// Generate master key and chain code
	h := hmac.New(sha512.New, hmacKey)
	h.Write(seed)
	sum := h.Sum(nil)

	// First 32 bytes are the private key, last 32 bytes are the chain code
	key := sum[:32]
	chainCode := sum[32:]

	// Derive each level of the path (all hardened for Ed25519)
	for _, index := range path {
		// Add hardened offset (0x80000000)
		hardenedIndex := index + 0x80000000 //nolint:mnd

		// Prepare data for HMAC: 0x00 || key || index
		data := make([]byte, 37) //nolint:mnd
		data[0] = 0x00
		copy(data[1:33], key)
		binary.BigEndian.PutUint32(data[33:], hardenedIndex)

		// Compute HMAC-SHA512
		h = hmac.New(sha512.New, chainCode)
		h.Write(data)
		sum = h.Sum(nil)

		// Update key and chain code
		key = sum[:32]
		chainCode = sum[32:]
	}

	return key
}

// DeriveMoneroAddress derives a Monero address from a polyseed mnemonic phrase.
// The function decodes the polyseed to extract the seed bytes, then derives
// the Monero spend and view keys from it.
//
// Parameters:
//   - mnemonic: A valid 16-word polyseed mnemonic phrase
//
// Returns:
//   - address: The Monero primary address (starts with "4")
//   - error: Any error that occurred during derivation
func DeriveMoneroAddress(mnemonic string) (string, error) {
	// Decode the polyseed mnemonic (auto-detects language)
	seed, _, err := polyseed.Decode(mnemonic, polyseed.CoinMonero)
	if err != nil {
		return "", fmt.Errorf("failed to decode polyseed mnemonic: %w", err)
	}
	defer seed.Free()

	// Derive the spend private key (32 bytes) from polyseed.
	// The polyseed Keygen() function returns seed bytes that need to be
	// reduced to a valid Ed25519 scalar using sc_reduce32.
	const polyseedKeySize = 32
	spendKeyBytes := seed.Keygen(polyseed.CoinMonero, polyseedKeySize)

	// Reduce the key bytes to a valid Ed25519 scalar.
	// This performs sc_reduce32 without any hashing - the key bytes are used directly.
	reducedKey := scReduce32(spendKeyBytes)

	// Create Monero private key from the reduced bytes.
	spendPrivKey, err := utils.NewPrivateKey(hex.EncodeToString(reducedKey))
	if err != nil {
		return "", fmt.Errorf("failed to create spend private key: %w", err)
	}

	// Create Monero key pair from the spend private key
	// This automatically derives the view key from the spend key
	keyPair, err := utils.NewFullKeyPairSpendPrivateKey(spendPrivKey)
	if err != nil {
		return "", fmt.Errorf("failed to create Monero key pair: %w", err)
	}

	// Get the public keys
	spendPubKey := keyPair.SpendKeyPair().PublicKey().Bytes()
	viewPubKey := keyPair.ViewKeyPair().PublicKey().Bytes()

	// Construct the address bytes: prefix (1) + spend pubkey (32) + view pubkey (32) + checksum (4)
	// Mainnet primary address prefix is 0x12
	addrData := make([]byte, 65) //nolint:mnd // 1 + 32 + 32
	addrData[0] = 0x12           // Mainnet primary address prefix
	copy(addrData[1:33], spendPubKey)
	copy(addrData[33:65], viewPubKey)

	// Calculate checksum (first 4 bytes of Keccak256 hash)
	checksum, err := utils.Keccak256Hash(addrData)
	if err != nil {
		return "", fmt.Errorf("failed to calculate checksum: %w", err)
	}

	// Append checksum to address data
	fullAddr := append(addrData, checksum[:4]...)

	// Encode using Monero's base58 encoding
	encoded, err := utils.EncodeMoneroAddress(fullAddr)
	if err != nil {
		return "", fmt.Errorf("failed to encode address: %w", err)
	}

	return string(encoded), nil
}

// MoneroKeys contains the primary address and subaddresses derived from a polyseed.
type MoneroKeys struct {
	// PrimaryAddress is the main Monero address (starts with "4")
	PrimaryAddress string
	// Subaddresses is a list of subaddresses (start with "8")
	// Index 0 is subaddress (0,1), index 1 is (0,2), etc.
	Subaddresses []string
}

// DeriveMoneroKeys derives a Monero primary address and subaddresses from a polyseed mnemonic.
// The function decodes the polyseed to extract the seed bytes, then derives
// the Monero spend and view keys, and generates the requested number of subaddresses.
//
// Parameters:
//   - mnemonic: A valid 16-word polyseed mnemonic phrase
//   - numSubaddresses: Number of subaddresses to generate (0 for none)
//
// Returns:
//   - MoneroKeys: Contains the primary address and subaddresses
//   - error: Any error that occurred during derivation
func DeriveMoneroKeys(mnemonic string, numSubaddresses int) (*MoneroKeys, error) {
	// Decode the polyseed mnemonic (auto-detects language)
	seed, _, err := polyseed.Decode(mnemonic, polyseed.CoinMonero)
	if err != nil {
		return nil, fmt.Errorf("failed to decode polyseed mnemonic: %w", err)
	}
	defer seed.Free()

	// Derive the spend private key (32 bytes) from polyseed
	const polyseedKeySize = 32
	spendKeyBytes := seed.Keygen(polyseed.CoinMonero, polyseedKeySize)

	// Reduce the key bytes to a valid Ed25519 scalar
	reducedKey := scReduce32(spendKeyBytes)

	// Create Monero private key from the reduced bytes
	spendPrivKey, err := utils.NewPrivateKey(hex.EncodeToString(reducedKey))
	if err != nil {
		return nil, fmt.Errorf("failed to create spend private key: %w", err)
	}

	// Create Monero key pair from the spend private key
	keyPair, err := utils.NewFullKeyPairSpendPrivateKey(spendPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create Monero key pair: %w", err)
	}

	// Get the keys
	viewSecKey := keyPair.ViewKeyPair().PrivateKey().Bytes()
	spendPubKey := keyPair.SpendKeyPair().PublicKey().Bytes()
	viewPubKey := keyPair.ViewKeyPair().PublicKey().Bytes()

	// Build primary address
	primaryAddr, err := buildMoneroAddress(0x12, spendPubKey, viewPubKey) //nolint:mnd
	if err != nil {
		return nil, fmt.Errorf("failed to build primary address: %w", err)
	}

	// Generate subaddresses
	subaddresses := make([]string, 0, numSubaddresses)
	for i := uint32(1); i <= uint32(numSubaddresses); i++ { //nolint:gosec // numSubaddresses is always small (single digits)
		subaddr, err := deriveMoneroSubaddress(viewSecKey, spendPubKey, 0, i)
		if err != nil {
			return nil, fmt.Errorf("failed to derive subaddress (0,%d): %w", i, err)
		}
		subaddresses = append(subaddresses, subaddr)
	}

	return &MoneroKeys{
		PrimaryAddress: primaryAddr,
		Subaddresses:   subaddresses,
	}, nil
}

// buildMoneroAddress constructs a Monero address from public keys and a prefix.
func buildMoneroAddress(prefix byte, spendPubKey, viewPubKey []byte) (string, error) {
	addrData := make([]byte, 65) //nolint:mnd // 1 + 32 + 32
	addrData[0] = prefix
	copy(addrData[1:33], spendPubKey)
	copy(addrData[33:65], viewPubKey)

	checksum, err := utils.Keccak256Hash(addrData)
	if err != nil {
		return "", fmt.Errorf("failed to calculate checksum: %w", err)
	}

	fullAddr := append(addrData, checksum[:4]...)
	encoded, err := utils.EncodeMoneroAddress(fullAddr)
	if err != nil {
		return "", fmt.Errorf("failed to encode address: %w", err)
	}

	return string(encoded), nil
}

// deriveMoneroSubaddress derives a Monero subaddress at the given index.
// Subaddresses use a different derivation: D_ij = B + m*G, C_ij = a*D_ij
// where m = Hs("SubAddr" || a || i || j), B is spend public, a is view secret.
func deriveMoneroSubaddress(viewSecretKey, spendPubKey []byte, major, minor uint32) (string, error) {
	if major == 0 && minor == 0 {
		return "", fmt.Errorf("(0,0) is the primary address, not a subaddress")
	}

	// Compute m = Hs("SubAddr" || view_secret || major || minor)
	prefix := []byte("SubAddr\x00") // "SubAddr" with null terminator
	majorBytes := make([]byte, 4)   //nolint:mnd
	minorBytes := make([]byte, 4)   //nolint:mnd
	binary.LittleEndian.PutUint32(majorBytes, major)
	binary.LittleEndian.PutUint32(minorBytes, minor)

	data := make([]byte, 0, len(prefix)+32+8) //nolint:mnd
	data = append(data, prefix...)
	data = append(data, viewSecretKey...)
	data = append(data, majorBytes...)
	data = append(data, minorBytes...)

	// Hash to scalar: Hs(data) = sc_reduce32(keccak256(data))
	hash, err := utils.Keccak256Hash(data)
	if err != nil {
		return "", fmt.Errorf("failed to hash subaddress data: %w", err)
	}
	m := scReduce32(hash)

	// Convert m to edwards25519 scalar
	mScalar, err := edwards25519.NewScalar().SetCanonicalBytes(m)
	if err != nil {
		return "", fmt.Errorf("failed to create scalar from m: %w", err)
	}

	// Compute m*G (base point multiplication)
	mG := edwards25519.NewIdentityPoint().ScalarBaseMult(mScalar)

	// Parse spend public key as a point
	spendPubPoint, err := edwards25519.NewIdentityPoint().SetBytes(spendPubKey)
	if err != nil {
		return "", fmt.Errorf("failed to parse spend public key: %w", err)
	}

	// D_ij = B + m*G (subaddress spend public key)
	subSpendPub := edwards25519.NewIdentityPoint().Add(spendPubPoint, mG)

	// Parse view secret key as scalar
	viewSecScalar, err := edwards25519.NewScalar().SetCanonicalBytes(viewSecretKey)
	if err != nil {
		return "", fmt.Errorf("failed to create scalar from view secret: %w", err)
	}

	// C_ij = a * D_ij (subaddress view public key)
	subViewPub := edwards25519.NewIdentityPoint().ScalarMult(viewSecScalar, subSpendPub)

	// Build subaddress with prefix 0x2A (42 decimal)
	return buildMoneroAddress(0x2A, subSpendPub.Bytes(), subViewPub.Bytes()) //nolint:mnd
}

// scReduce32 reduces a 32-byte value to a valid Ed25519 scalar.
// This ensures the value is in canonical form (< L) for use as a Monero private key.
// L = 2^252 + 27742317777372353535851937790883648493 (the Ed25519 curve order).
//
// This function performs proper modular reduction mod L using the edwards25519 library.
// The input bytes are padded to 64 bytes and then reduced using SetUniformBytes,
// which performs the correct sc_reduce operation.
func scReduce32(input []byte) []byte {
	if len(input) != 32 { //nolint:mnd
		return input
	}

	// First try to interpret as a canonical scalar directly
	scalar, err := edwards25519.NewScalar().SetCanonicalBytes(input)
	if err == nil {
		return scalar.Bytes()
	}

	// If not canonical, perform proper modular reduction.
	// Pad to 64 bytes and use SetUniformBytes which performs sc_reduce.
	padded := make([]byte, 64) //nolint:mnd
	copy(padded, input)

	scalar, err = edwards25519.NewScalar().SetUniformBytes(padded)
	if err != nil {
		// Fallback: clear high bits (should rarely happen)
		result := make([]byte, 32) //nolint:mnd
		copy(result, input)
		result[31] &= 0x0F
		return result
	}

	return scalar.Bytes()
}

// Extended key version bytes for SLIP-0132 encoding.
// These are used to encode extended keys with version prefixes that indicate
// the derivation path standard (BIP44, BIP49, BIP84).
const (
	// BIP49 SegWit (ypub/yprv).
	ypubVersion uint32 = 0x049D7CB2
	yprvVersion uint32 = 0x049D7878
	// BIP84 Native SegWit (zpub/zprv).
	zpubVersion uint32 = 0x04B24746
	zprvVersion uint32 = 0x04B2430C
	// BIP48 Multisig P2SH-P2WSH (Ypub/Yprv). Uppercase denotes multisig.
	multisigYpubVersion uint32 = 0x0295B43F
	multisigYprvVersion uint32 = 0x0295B005
	// BIP48 Multisig P2WSH (Zpub/Zprv). Uppercase denotes multisig.
	multisigZpubVersion uint32 = 0x02AA7ED3
	multisigZprvVersion uint32 = 0x02AA7A99
)

// BitcoinKeys contains the address and private key (WIF) for a Bitcoin derivation.
type BitcoinKeys struct {
	Address    string
	PrivateWIF string
}

// BitcoinExtendedKeys contains the extended public and private keys at the account level.
type BitcoinExtendedKeys struct {
	ExtendedPublicKey  string
	ExtendedPrivateKey string
}

// BitcoinMultisigExtendedKeys contains both the specific format (Ypub/Yprv or Zpub/Zprv)
// and the standard format (xpub/xprv) for multisig extended keys.
// The standard keys are nested conceptually below the specific keys.
type BitcoinMultisigExtendedKeys struct {
	// ExtendedPublicKey is the specific format (e.g., Ypub or Zpub)
	ExtendedPublicKey string
	// ExtendedPrivateKey is the specific format (e.g., Yprv or Zprv)
	ExtendedPrivateKey string
	// StandardPublicKey is the standard xpub format
	StandardPublicKey string
	// StandardPrivateKey is the standard xprv format
	StandardPrivateKey string
}

// deriveBIP32Path derives a key at the given BIP32 path from a master key.
// The path is specified as a slice of uint32 values, where values >= 0x80000000
// are hardened derivations.
func deriveBIP32Path(masterKey *hdkeychain.ExtendedKey, path []uint32) (*hdkeychain.ExtendedKey, error) {
	key := masterKey
	var err error
	for _, index := range path {
		key, err = key.Derive(index)
		if err != nil {
			return nil, fmt.Errorf("failed to derive at index %d: %w", index, err)
		}
	}
	return key, nil
}

// DeriveBitcoinLegacyKeys derives a Bitcoin Legacy P2PKH address and its WIF private key.
// The function follows BIP44 standard with derivation path m/44'/0'/0'/0/0.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - BitcoinKeys: The address and WIF-encoded private key
//   - error: Any error that occurred during derivation
func DeriveBitcoinLegacyKeys(mnemonic string, bip39Passphrase string) (*BitcoinKeys, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive BIP44 path: m/44'/0'/0'/0/0
	path := []uint32{
		hdkeychain.HardenedKeyStart + 44, // purpose
		hdkeychain.HardenedKeyStart + 0,  // coin type (Bitcoin)
		hdkeychain.HardenedKeyStart + 0,  // account
		0,                                // change (external)
		0,                                // address index
	}
	addressKey, err := deriveBIP32Path(masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("failed to derive address key: %w", err)
	}

	// Get the public key and create P2PKH address
	pubKey, err := addressKey.ECPubKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	addr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create address: %w", err)
	}

	// Get the private key in WIF format
	privKey, err := addressKey.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}
	wif, err := btcutil.NewWIF(privKey, &chaincfg.MainNetParams, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create WIF: %w", err)
	}

	return &BitcoinKeys{
		Address:    addr.EncodeAddress(),
		PrivateWIF: wif.String(),
	}, nil
}

// DeriveBitcoinSegwitKeys derives a Bitcoin SegWit P2SH-P2WPKH address and its WIF private key.
// The function follows BIP49 standard with derivation path m/49'/0'/0'/0/0.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - BitcoinKeys: The address and WIF-encoded private key
//   - error: Any error that occurred during derivation
func DeriveBitcoinSegwitKeys(mnemonic string, bip39Passphrase string) (*BitcoinKeys, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive BIP49 path: m/49'/0'/0'/0/0
	path := []uint32{
		hdkeychain.HardenedKeyStart + 49, // purpose (BIP49)
		hdkeychain.HardenedKeyStart + 0,  // coin type (Bitcoin)
		hdkeychain.HardenedKeyStart + 0,  // account
		0,                                // change (external)
		0,                                // address index
	}
	addressKey, err := deriveBIP32Path(masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("failed to derive address key: %w", err)
	}

	// Get the public key
	pubKey, err := addressKey.ECPubKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Create P2WPKH (witness) address first
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	witnessAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create witness address: %w", err)
	}

	// Wrap in P2SH to create P2SH-P2WPKH address (starts with "3")
	script, err := txscript.PayToAddrScript(witnessAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create script: %w", err)
	}
	addr, err := btcutil.NewAddressScriptHash(script, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create P2SH address: %w", err)
	}

	// Get the private key in WIF format
	privKey, err := addressKey.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}
	wif, err := btcutil.NewWIF(privKey, &chaincfg.MainNetParams, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create WIF: %w", err)
	}

	return &BitcoinKeys{
		Address:    addr.EncodeAddress(),
		PrivateWIF: wif.String(),
	}, nil
}

// DeriveBitcoinNativeSegwitKeys derives a Bitcoin Native SegWit P2WPKH address and its WIF private key.
// The function follows BIP84 standard with derivation path m/84'/0'/0'/0/0.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - BitcoinKeys: The address and WIF-encoded private key
//   - error: Any error that occurred during derivation
func DeriveBitcoinNativeSegwitKeys(mnemonic string, bip39Passphrase string) (*BitcoinKeys, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive BIP84 path: m/84'/0'/0'/0/0
	path := []uint32{
		hdkeychain.HardenedKeyStart + 84, // purpose (BIP84)
		hdkeychain.HardenedKeyStart + 0,  // coin type (Bitcoin)
		hdkeychain.HardenedKeyStart + 0,  // account
		0,                                // change (external)
		0,                                // address index
	}
	addressKey, err := deriveBIP32Path(masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("failed to derive address key: %w", err)
	}

	// Get the public key and create P2WPKH address
	pubKey, err := addressKey.ECPubKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	addr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create address: %w", err)
	}

	// Get the private key in WIF format
	privKey, err := addressKey.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}
	wif, err := btcutil.NewWIF(privKey, &chaincfg.MainNetParams, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create WIF: %w", err)
	}

	return &BitcoinKeys{
		Address:    addr.EncodeAddress(),
		PrivateWIF: wif.String(),
	}, nil
}

// encodeExtendedKey encodes an extended key with a custom version prefix.
// This is used to create ypub/yprv, zpub/zprv, and multisig variants.
func encodeExtendedKey(key *hdkeychain.ExtendedKey, version uint32) string {
	// Get the serialized key (78 bytes)
	serialized := key.String()

	// Decode the base58check (extended keys use 4-byte version, not 1-byte)
	decoded, err := base58.Decode(serialized)
	if err != nil {
		return ""
	}

	// Verify we have enough data (78 bytes + 4 bytes checksum = 82 bytes)
	if len(decoded) < 82 { //nolint:mnd
		return ""
	}

	// Get payload without checksum
	payload := decoded[:78]

	// Replace the first 4 bytes (version) with our custom version
	versionBytes := make([]byte, 4) //nolint:mnd
	binary.BigEndian.PutUint32(versionBytes, version)
	copy(payload[0:4], versionBytes)

	// Calculate new checksum (double SHA256, first 4 bytes)
	firstHash := sha256.Sum256(payload)
	secondHash := sha256.Sum256(firstHash[:])
	checksum := secondHash[:4]

	// Append checksum and encode
	result := append(payload, checksum...)

	return base58.Encode(result)
}

// DeriveBitcoinMasterFingerprint derives the master key fingerprint from a BIP39 mnemonic.
// The fingerprint is the first 4 bytes of HASH160(compressed_master_public_key),
// encoded as a lowercase hex string (8 characters). This is commonly used in
// wallet descriptors and PSBTs (e.g., [d219d86d/48'/0'/0'/2']xpub...).
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - fingerprint: The 4-byte master fingerprint as a lowercase hex string
//   - error: Any error that occurred during derivation
func DeriveBitcoinMasterFingerprint(mnemonic string, bip39Passphrase string) (string, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return "", fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("failed to create master key: %w", err)
	}

	// Get the master public key
	masterPubKey, err := masterKey.ECPubKey()
	if err != nil {
		return "", fmt.Errorf("failed to get master public key: %w", err)
	}

	// Compute HASH160 of the compressed public key and take the first 4 bytes
	pubKeyHash := btcutil.Hash160(masterPubKey.SerializeCompressed())
	fingerprint := pubKeyHash[:4]

	return hex.EncodeToString(fingerprint), nil
}

// DeriveBitcoinMasterExtendedKeys derives the master extended public and private keys.
// Returns xpub and xprv at the master level (m).
// This is the root of the HD wallet tree, before any BIP44/49/84 derivation.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - BitcoinExtendedKeys: The xpub and xprv at master level
//   - error: Any error that occurred during derivation
func DeriveBitcoinMasterExtendedKeys(mnemonic string, bip39Passphrase string) (*BitcoinExtendedKeys, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Get the public key version (neuter removes the private key)
	masterPubKey, err := masterKey.Neuter()
	if err != nil {
		return nil, fmt.Errorf("failed to neuter key: %w", err)
	}

	return &BitcoinExtendedKeys{
		ExtendedPublicKey:  masterPubKey.String(),
		ExtendedPrivateKey: masterKey.String(),
	}, nil
}

// DeriveBitcoinLegacyExtendedKeys derives the extended public and private keys for BIP44 Legacy.
// Returns xpub and xprv at the account level (m/44'/0'/0').
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - BitcoinExtendedKeys: The xpub and xprv at account level
//   - error: Any error that occurred during derivation
func DeriveBitcoinLegacyExtendedKeys(mnemonic string, bip39Passphrase string) (*BitcoinExtendedKeys, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive to account level: m/44'/0'/0'
	path := []uint32{
		hdkeychain.HardenedKeyStart + 44, // purpose
		hdkeychain.HardenedKeyStart + 0,  // coin type (Bitcoin)
		hdkeychain.HardenedKeyStart + 0,  // account
	}
	accountKey, err := deriveBIP32Path(masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("failed to derive account key: %w", err)
	}

	// Get the public key version (neuter removes the private key)
	accountPubKey, err := accountKey.Neuter()
	if err != nil {
		return nil, fmt.Errorf("failed to neuter key: %w", err)
	}

	return &BitcoinExtendedKeys{
		ExtendedPublicKey:  accountPubKey.String(), // Already xpub format
		ExtendedPrivateKey: accountKey.String(),    // Already xprv format
	}, nil
}

// DeriveBitcoinSegwitExtendedKeys derives the extended public and private keys for BIP49 SegWit.
// Returns ypub and yprv at the account level (m/49'/0'/0').
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - BitcoinExtendedKeys: The ypub and yprv at account level
//   - error: Any error that occurred during derivation
func DeriveBitcoinSegwitExtendedKeys(mnemonic string, bip39Passphrase string) (*BitcoinExtendedKeys, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive to account level: m/49'/0'/0'
	path := []uint32{
		hdkeychain.HardenedKeyStart + 49, // purpose (BIP49)
		hdkeychain.HardenedKeyStart + 0,  // coin type (Bitcoin)
		hdkeychain.HardenedKeyStart + 0,  // account
	}
	accountKey, err := deriveBIP32Path(masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("failed to derive account key: %w", err)
	}

	// Get the public key version (neuter removes the private key)
	accountPubKey, err := accountKey.Neuter()
	if err != nil {
		return nil, fmt.Errorf("failed to neuter key: %w", err)
	}

	// Encode with ypub/yprv version bytes
	return &BitcoinExtendedKeys{
		ExtendedPublicKey:  encodeExtendedKey(accountPubKey, ypubVersion),
		ExtendedPrivateKey: encodeExtendedKey(accountKey, yprvVersion),
	}, nil
}

// DeriveBitcoinNativeSegwitExtendedKeys derives the extended public and private keys for BIP84 Native SegWit.
// Returns zpub and zprv at the account level (m/84'/0'/0').
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - BitcoinExtendedKeys: The zpub and zprv at account level
//   - error: Any error that occurred during derivation
func DeriveBitcoinNativeSegwitExtendedKeys(mnemonic string, bip39Passphrase string) (*BitcoinExtendedKeys, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive to account level: m/84'/0'/0'
	path := []uint32{
		hdkeychain.HardenedKeyStart + 84, // purpose (BIP84)
		hdkeychain.HardenedKeyStart + 0,  // coin type (Bitcoin)
		hdkeychain.HardenedKeyStart + 0,  // account
	}
	accountKey, err := deriveBIP32Path(masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("failed to derive account key: %w", err)
	}

	// Get the public key version (neuter removes the private key)
	accountPubKey, err := accountKey.Neuter()
	if err != nil {
		return nil, fmt.Errorf("failed to neuter key: %w", err)
	}

	// Encode with zpub/zprv version bytes
	return &BitcoinExtendedKeys{
		ExtendedPublicKey:  encodeExtendedKey(accountPubKey, zpubVersion),
		ExtendedPrivateKey: encodeExtendedKey(accountKey, zprvVersion),
	}, nil
}

// DeriveBitcoinMultisigLegacyKeys derives a 1-of-1 multisig P2SH address and its WIF private key.
// The function follows BIP48 standard with derivation path m/48'/0'/0'/0'/0/0.
// Script type 0' indicates P2SH (legacy multisig).
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - BitcoinKeys: The P2SH multisig address and WIF-encoded private key
//   - error: Any error that occurred during derivation
func DeriveBitcoinMultisigLegacyKeys(mnemonic string, bip39Passphrase string) (*BitcoinKeys, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive BIP48 path: m/48'/0'/0'/0'/0/0
	// 48' = purpose (BIP48 multisig)
	// 0' = coin type (Bitcoin)
	// 0' = account
	// 0' = script type (P2SH legacy)
	// 0 = change (external)
	// 0 = address index
	path := []uint32{
		hdkeychain.HardenedKeyStart + 48, // purpose (BIP48)
		hdkeychain.HardenedKeyStart + 0,  // coin type (Bitcoin)
		hdkeychain.HardenedKeyStart + 0,  // account
		hdkeychain.HardenedKeyStart + 0,  // script type (P2SH)
		0,                                // change (external)
		0,                                // address index
	}
	addressKey, err := deriveBIP32Path(masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("failed to derive address key: %w", err)
	}

	// Get the public key
	pubKey, err := addressKey.ECPubKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Create 1-of-1 multisig script: OP_1 <pubkey> OP_1 OP_CHECKMULTISIG
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_1)
	builder.AddData(pubKey.SerializeCompressed())
	builder.AddOp(txscript.OP_1)
	builder.AddOp(txscript.OP_CHECKMULTISIG)
	multisigScript, err := builder.Script()
	if err != nil {
		return nil, fmt.Errorf("failed to build multisig script: %w", err)
	}

	// Create P2SH address from the multisig script
	scriptHash := btcutil.Hash160(multisigScript)
	addr, err := btcutil.NewAddressScriptHashFromHash(scriptHash, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create P2SH address: %w", err)
	}

	// Get the private key in WIF format
	privKey, err := addressKey.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}
	wif, err := btcutil.NewWIF(privKey, &chaincfg.MainNetParams, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create WIF: %w", err)
	}

	return &BitcoinKeys{
		Address:    addr.EncodeAddress(),
		PrivateWIF: wif.String(),
	}, nil
}

// DeriveBitcoinMultisigSegwitKeys derives a 1-of-1 multisig P2SH-P2WSH address and its WIF private key.
// The function follows BIP48 standard with derivation path m/48'/0'/0'/1'/0/0.
// Script type 1' indicates P2SH-P2WSH (nested SegWit multisig).
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - BitcoinKeys: The P2SH-P2WSH multisig address and WIF-encoded private key
//   - error: Any error that occurred during derivation
func DeriveBitcoinMultisigSegwitKeys(mnemonic string, bip39Passphrase string) (*BitcoinKeys, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive BIP48 path: m/48'/0'/0'/1'/0/0
	// 48' = purpose (BIP48 multisig)
	// 0' = coin type (Bitcoin)
	// 0' = account
	// 1' = script type (P2SH-P2WSH nested SegWit)
	// 0 = change (external)
	// 0 = address index
	path := []uint32{
		hdkeychain.HardenedKeyStart + 48, // purpose (BIP48)
		hdkeychain.HardenedKeyStart + 0,  // coin type (Bitcoin)
		hdkeychain.HardenedKeyStart + 0,  // account
		hdkeychain.HardenedKeyStart + 1,  // script type (P2SH-P2WSH)
		0,                                // change (external)
		0,                                // address index
	}
	addressKey, err := deriveBIP32Path(masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("failed to derive address key: %w", err)
	}

	// Get the public key
	pubKey, err := addressKey.ECPubKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Create 1-of-1 multisig witness script: OP_1 <pubkey> OP_1 OP_CHECKMULTISIG
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_1)
	builder.AddData(pubKey.SerializeCompressed())
	builder.AddOp(txscript.OP_1)
	builder.AddOp(txscript.OP_CHECKMULTISIG)
	witnessScript, err := builder.Script()
	if err != nil {
		return nil, fmt.Errorf("failed to build witness script: %w", err)
	}

	// Create P2WSH address from the witness script
	witnessScriptHash := sha256.Sum256(witnessScript)
	p2wshAddr, err := btcutil.NewAddressWitnessScriptHash(witnessScriptHash[:], &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create P2WSH address: %w", err)
	}

	// Wrap in P2SH to create P2SH-P2WSH address
	p2wshScript, err := txscript.PayToAddrScript(p2wshAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create P2WSH script: %w", err)
	}
	addr, err := btcutil.NewAddressScriptHash(p2wshScript, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create P2SH address: %w", err)
	}

	// Get the private key in WIF format
	privKey, err := addressKey.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}
	wif, err := btcutil.NewWIF(privKey, &chaincfg.MainNetParams, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create WIF: %w", err)
	}

	return &BitcoinKeys{
		Address:    addr.EncodeAddress(),
		PrivateWIF: wif.String(),
	}, nil
}

// DeriveBitcoinMultisigNativeSegwitKeys derives a 1-of-1 multisig P2WSH address and its WIF private key.
// The function follows BIP48 standard with derivation path m/48'/0'/0'/2'/0/0.
// Script type 2' indicates P2WSH (native SegWit multisig).
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - BitcoinKeys: The P2WSH multisig address and WIF-encoded private key
//   - error: Any error that occurred during derivation
func DeriveBitcoinMultisigNativeSegwitKeys(mnemonic string, bip39Passphrase string) (*BitcoinKeys, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive BIP48 path: m/48'/0'/0'/2'/0/0
	// 48' = purpose (BIP48 multisig)
	// 0' = coin type (Bitcoin)
	// 0' = account
	// 2' = script type (P2WSH native SegWit)
	// 0 = change (external)
	// 0 = address index
	path := []uint32{
		hdkeychain.HardenedKeyStart + 48, // purpose (BIP48)
		hdkeychain.HardenedKeyStart + 0,  // coin type (Bitcoin)
		hdkeychain.HardenedKeyStart + 0,  // account
		hdkeychain.HardenedKeyStart + 2,  // script type (P2WSH)
		0,                                // change (external)
		0,                                // address index
	}
	addressKey, err := deriveBIP32Path(masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("failed to derive address key: %w", err)
	}

	// Get the public key
	pubKey, err := addressKey.ECPubKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Create 1-of-1 multisig witness script: OP_1 <pubkey> OP_1 OP_CHECKMULTISIG
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_1)
	builder.AddData(pubKey.SerializeCompressed())
	builder.AddOp(txscript.OP_1)
	builder.AddOp(txscript.OP_CHECKMULTISIG)
	witnessScript, err := builder.Script()
	if err != nil {
		return nil, fmt.Errorf("failed to build witness script: %w", err)
	}

	// Create P2WSH address from the witness script (starts with "bc1q" for 20-byte hash or "bc1q" for 32-byte)
	witnessScriptHash := sha256.Sum256(witnessScript)
	addr, err := btcutil.NewAddressWitnessScriptHash(witnessScriptHash[:], &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create P2WSH address: %w", err)
	}

	// Get the private key in WIF format
	privKey, err := addressKey.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}
	wif, err := btcutil.NewWIF(privKey, &chaincfg.MainNetParams, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create WIF: %w", err)
	}

	return &BitcoinKeys{
		Address:    addr.EncodeAddress(),
		PrivateWIF: wif.String(),
	}, nil
}

// DeriveBitcoinMultisigLegacyExtendedKeys derives extended keys for BIP48 Legacy multisig.
// Returns xpub and xprv at the account/script level (m/48'/0'/0'/0').
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - BitcoinExtendedKeys: The xpub and xprv at account level
//   - error: Any error that occurred during derivation
func DeriveBitcoinMultisigLegacyExtendedKeys(mnemonic string, bip39Passphrase string) (*BitcoinExtendedKeys, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive to account/script level: m/48'/0'/0'/0'
	path := []uint32{
		hdkeychain.HardenedKeyStart + 48, // purpose (BIP48)
		hdkeychain.HardenedKeyStart + 0,  // coin type (Bitcoin)
		hdkeychain.HardenedKeyStart + 0,  // account
		hdkeychain.HardenedKeyStart + 0,  // script type (P2SH)
	}
	accountKey, err := deriveBIP32Path(masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("failed to derive account key: %w", err)
	}

	// Get the public key version (neuter removes the private key)
	accountPubKey, err := accountKey.Neuter()
	if err != nil {
		return nil, fmt.Errorf("failed to neuter key: %w", err)
	}

	// For legacy multisig, we use standard xpub/xprv
	return &BitcoinExtendedKeys{
		ExtendedPublicKey:  accountPubKey.String(),
		ExtendedPrivateKey: accountKey.String(),
	}, nil
}

// DeriveBitcoinMultisigSegwitExtendedKeys derives extended keys for BIP48 SegWit multisig.
// Returns Ypub/Yprv (SLIP-132 format) and xpub/xprv (standard format) at the account/script level (m/48'/0'/0'/1').
// Uppercase Y indicates multisig P2SH-P2WSH.
//
// The standard xpub/xprv keys are provided as nested alternatives to the specific Ypub/Yprv format:
//
//	Yprv ...
//	|_ xprv ...
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - BitcoinMultisigExtendedKeys: The Ypub/Yprv and xpub/xprv at account level
//   - error: Any error that occurred during derivation
func DeriveBitcoinMultisigSegwitExtendedKeys(mnemonic string, bip39Passphrase string) (*BitcoinMultisigExtendedKeys, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive to account/script level: m/48'/0'/0'/1'
	path := []uint32{
		hdkeychain.HardenedKeyStart + 48, // purpose (BIP48)
		hdkeychain.HardenedKeyStart + 0,  // coin type (Bitcoin)
		hdkeychain.HardenedKeyStart + 0,  // account
		hdkeychain.HardenedKeyStart + 1,  // script type (P2SH-P2WSH)
	}
	accountKey, err := deriveBIP32Path(masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("failed to derive account key: %w", err)
	}

	// Get the public key version (neuter removes the private key)
	accountPubKey, err := accountKey.Neuter()
	if err != nil {
		return nil, fmt.Errorf("failed to neuter key: %w", err)
	}

	// Return both Ypub/Yprv (SLIP-132) and standard xpub/xprv formats
	return &BitcoinMultisigExtendedKeys{
		ExtendedPublicKey:  encodeExtendedKey(accountPubKey, multisigYpubVersion),
		ExtendedPrivateKey: encodeExtendedKey(accountKey, multisigYprvVersion),
		StandardPublicKey:  accountPubKey.String(),
		StandardPrivateKey: accountKey.String(),
	}, nil
}

// DeriveBitcoinMultisigNativeSegwitExtendedKeys derives extended keys for BIP48 Native SegWit multisig.
// Returns Zpub/Zprv (SLIP-132 format) and xpub/xprv (standard format) at the account/script level (m/48'/0'/0'/2').
// Uppercase Z indicates multisig P2WSH.
//
// The standard xpub/xprv keys are provided as nested alternatives to the specific Zpub/Zprv format:
//
//	Zprv ...
//	|_ xprv ...
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - BitcoinMultisigExtendedKeys: The Zpub/Zprv and xpub/xprv at account level
//   - error: Any error that occurred during derivation
func DeriveBitcoinMultisigNativeSegwitExtendedKeys(mnemonic string, bip39Passphrase string) (*BitcoinMultisigExtendedKeys, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive to account/script level: m/48'/0'/0'/2'
	path := []uint32{
		hdkeychain.HardenedKeyStart + 48, // purpose (BIP48)
		hdkeychain.HardenedKeyStart + 0,  // coin type (Bitcoin)
		hdkeychain.HardenedKeyStart + 0,  // account
		hdkeychain.HardenedKeyStart + 2,  // script type (P2WSH)
	}
	accountKey, err := deriveBIP32Path(masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("failed to derive account key: %w", err)
	}

	// Get the public key version (neuter removes the private key)
	accountPubKey, err := accountKey.Neuter()
	if err != nil {
		return nil, fmt.Errorf("failed to neuter key: %w", err)
	}

	// Return both Zpub/Zprv (SLIP-132) and standard xpub/xprv formats
	return &BitcoinMultisigExtendedKeys{
		ExtendedPublicKey:  encodeExtendedKey(accountPubKey, multisigZpubVersion),
		ExtendedPrivateKey: encodeExtendedKey(accountKey, multisigZprvVersion),
		StandardPublicKey:  accountPubKey.String(),
		StandardPrivateKey: accountKey.String(),
	}, nil
}

// deriveBIPAddress is a helper that derives a secp256k1 address at
// m/purpose'/coinType'/0'/0/0 and returns the HASH160 of the compressed public key.
// This is the common pattern for BIP44/BIP84-based chains.
func deriveBIPAddress(mnemonic string, bip39Passphrase string, purpose uint32, coinType uint32) (pubKeyHash []byte, err error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive path: m/purpose'/coinType'/0'/0/0
	path := []uint32{
		hdkeychain.HardenedKeyStart + purpose,  // purpose (e.g. 44 for BIP44, 84 for BIP84)
		hdkeychain.HardenedKeyStart + coinType, // coin type
		hdkeychain.HardenedKeyStart + 0,        // account
		0,                                      // change (external)
		0,                                      // address index
	}
	addressKey, err := deriveBIP32Path(masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("failed to derive address key: %w", err)
	}

	// Get the compressed public key
	pubKey, err := addressKey.ECPubKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	compressed := pubKey.SerializeCompressed()
	hash := btcutil.Hash160(compressed)

	return hash, nil
}

// deriveBIP44Address is a convenience wrapper around deriveBIPAddress
// for BIP44 (purpose 44) derivation paths: m/44'/coinType'/0'/0/0.
func deriveBIP44Address(mnemonic string, bip39Passphrase string, coinType uint32) (pubKeyHash []byte, err error) {
	return deriveBIPAddress(mnemonic, bip39Passphrase, 44, coinType) //nolint:mnd
}

// encodeBase58Check encodes data with a version byte using Base58Check encoding.
// This is the standard encoding for Bitcoin-like addresses:
// Base58(version || payload || checksum) where checksum = SHA256(SHA256(version || payload))[:4].
func encodeBase58Check(version byte, payload []byte) string {
	// Prepend version byte
	data := make([]byte, 0, 1+len(payload)+4) //nolint:mnd
	data = append(data, version)
	data = append(data, payload...)

	// Calculate checksum: first 4 bytes of double SHA256
	firstHash := sha256.Sum256(data)
	secondHash := sha256.Sum256(firstHash[:])
	checksum := secondHash[:4]

	// Append checksum
	data = append(data, checksum...)

	return base58.Encode(data)
}

// encodeBech32Address encodes a witness program as a bech32 address with the given
// human-readable part (HRP) and witness version.
func encodeBech32Address(hrp string, witnessVersion byte, witnessProgram []byte) (string, error) {
	// Convert the witness program to 5-bit groups for bech32 encoding
	converted, err := bech32.ConvertBits(witnessProgram, 8, 5, true) //nolint:mnd
	if err != nil {
		return "", fmt.Errorf("failed to convert bits: %w", err)
	}

	// Prepend witness version
	data := make([]byte, 0, 1+len(converted))
	data = append(data, witnessVersion)
	data = append(data, converted...)

	// Encode as bech32
	encoded, err := bech32.Encode(hrp, data)
	if err != nil {
		return "", fmt.Errorf("failed to encode bech32: %w", err)
	}

	return encoded, nil
}

// DeriveLitecoinAddress derives a Litecoin native SegWit (P2WPKH) address from a BIP39 mnemonic.
// The function follows BIP84 standard with derivation path m/84'/2'/0'/0/0.
// It returns a Bech32 address (starts with "ltc1") for Litecoin mainnet.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - address: The Litecoin P2WPKH address (starts with "ltc1")
//   - error: Any error that occurred during derivation
func DeriveLitecoinAddress(mnemonic string, bip39Passphrase string) (string, error) {
	// Derive at m/84'/2'/0'/0/0 (BIP84 native SegWit, coin type 2 = Litecoin)
	pubKeyHash, err := deriveBIPAddress(mnemonic, bip39Passphrase, 84, 2) //nolint:mnd
	if err != nil {
		return "", fmt.Errorf("failed to derive Litecoin key: %w", err)
	}

	// Encode as Bech32 with HRP "ltc" and witness version 0
	addr, err := encodeBech32Address("ltc", 0, pubKeyHash)
	if err != nil {
		return "", fmt.Errorf("failed to encode Litecoin address: %w", err)
	}

	return addr, nil
}

// DeriveDogecoinAddress derives a Dogecoin P2PKH address from a BIP39 mnemonic.
// The function follows BIP44 standard with derivation path m/44'/3'/0'/0/0.
// It returns a Base58Check address (starts with "D") for Dogecoin mainnet.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - address: The Dogecoin P2PKH address (starts with "D")
//   - error: Any error that occurred during derivation
func DeriveDogecoinAddress(mnemonic string, bip39Passphrase string) (string, error) {
	// Derive at m/44'/3'/0'/0/0 (coin type 3 = Dogecoin)
	pubKeyHash, err := deriveBIP44Address(mnemonic, bip39Passphrase, 3) //nolint:mnd
	if err != nil {
		return "", fmt.Errorf("failed to derive Dogecoin key: %w", err)
	}

	// Encode as Base58Check with version byte 0x1E (Dogecoin mainnet P2PKH, produces "D...")
	return encodeBase58Check(0x1E, pubKeyHash), nil //nolint:mnd
}

// rippleAlphabet is the custom Base58 alphabet used by the XRP Ledger.
const rippleAlphabet = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"

// DeriveRippleAddress derives an XRP Ledger address from a BIP39 mnemonic.
// The function follows BIP44 standard with derivation path m/44'/144'/0'/0/0.
// It returns a Ripple Base58Check address (starts with "r").
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - address: The XRP address (starts with "r")
//   - error: Any error that occurred during derivation
func DeriveRippleAddress(mnemonic string, bip39Passphrase string) (string, error) {
	// Derive at m/44'/144'/0'/0/0 (coin type 144 = XRP)
	pubKeyHash, err := deriveBIP44Address(mnemonic, bip39Passphrase, 144) //nolint:mnd
	if err != nil {
		return "", fmt.Errorf("failed to derive Ripple key: %w", err)
	}

	// Encode as Ripple Base58Check with version byte 0x00
	return encodeRippleBase58Check(0x00, pubKeyHash), nil //nolint:mnd
}

// encodeRippleBase58Check encodes data using Ripple's custom Base58Check format.
// It uses the same checksum scheme as Bitcoin (double SHA256) but a different alphabet.
func encodeRippleBase58Check(version byte, payload []byte) string {
	// Build versioned payload
	data := make([]byte, 0, 1+len(payload)+4) //nolint:mnd
	data = append(data, version)
	data = append(data, payload...)

	// Calculate checksum: first 4 bytes of double SHA256
	firstHash := sha256.Sum256(data)
	secondHash := sha256.Sum256(firstHash[:])
	checksum := secondHash[:4]
	data = append(data, checksum...)

	// Encode using Ripple's custom Base58 alphabet
	return encodeBase58WithAlphabet(data, rippleAlphabet)
}

// encodeBase58WithAlphabet encodes bytes using a custom Base58 alphabet.
func encodeBase58WithAlphabet(data []byte, alphabet string) string {
	// Use standard base58 encoding then translate the alphabet
	standardAlphabet := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	encoded := base58.Encode(data)

	// Build translation table from standard to custom alphabet
	var result strings.Builder
	result.Grow(len(encoded))
	for _, c := range encoded {
		idx := strings.IndexRune(standardAlphabet, c)
		if idx >= 0 {
			result.WriteByte(alphabet[idx])
		}
	}

	return result.String()
}

// DeriveCosmosAddress derives a Cosmos (ATOM) address from a BIP39 mnemonic.
// The function follows BIP44 standard with derivation path m/44'/118'/0'/0/0.
// It returns a Bech32 address with the "cosmos" prefix (starts with "cosmos1").
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - address: The Cosmos address (starts with "cosmos1")
//   - error: Any error that occurred during derivation
func DeriveCosmosAddress(mnemonic string, bip39Passphrase string) (string, error) {
	return deriveCosmosBech32Address(mnemonic, bip39Passphrase, 118, "cosmos") //nolint:mnd
}

// DeriveNobleAddress derives a Noble address from a BIP39 mnemonic.
// Noble uses the same key derivation as Cosmos (coin type 118) but with "noble" bech32 prefix.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - address: The Noble address (starts with "noble1")
//   - error: Any error that occurred during derivation
func DeriveNobleAddress(mnemonic string, bip39Passphrase string) (string, error) {
	return deriveCosmosBech32Address(mnemonic, bip39Passphrase, 118, "noble") //nolint:mnd
}

// deriveCosmosBech32Address derives a Cosmos-ecosystem Bech32 address.
// It uses secp256k1 at m/44'/coinType'/0'/0/0 and encodes the HASH160 of the
// compressed public key as Bech32 with the given human-readable prefix.
func deriveCosmosBech32Address(mnemonic string, bip39Passphrase string, coinType uint32, hrp string) (string, error) {
	// Derive the key at m/44'/coinType'/0'/0/0
	pubKeyHash, err := deriveBIP44Address(mnemonic, bip39Passphrase, coinType)
	if err != nil {
		return "", fmt.Errorf("failed to derive %s key: %w", hrp, err)
	}

	// Convert the 20-byte hash to 5-bit groups for bech32 encoding
	converted, err := bech32.ConvertBits(pubKeyHash, 8, 5, true) //nolint:mnd
	if err != nil {
		return "", fmt.Errorf("failed to convert bits for %s address: %w", hrp, err)
	}

	// Encode as bech32 (no witness version prefix for Cosmos)
	encoded, err := bech32.Encode(hrp, converted)
	if err != nil {
		return "", fmt.Errorf("failed to encode %s address: %w", hrp, err)
	}

	return encoded, nil
}

// DeriveStellarAddress derives a Stellar (XLM) address from a BIP39 mnemonic.
// The function follows SEP-0005 standard with derivation path m/44'/148'/0'
// using SLIP-0010 Ed25519 derivation.
// It returns a StrKey-encoded public key (starts with "G").
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - address: The Stellar address (starts with "G")
//   - error: Any error that occurred during derivation
func DeriveStellarAddress(mnemonic string, bip39Passphrase string) (string, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return "", fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Derive Ed25519 key using SLIP-0010 at m/44'/148'/0' (SEP-0005)
	key := deriveEd25519Key(seed, []uint32{44, 148, 0})

	// Generate Ed25519 public key from the derived private key
	privateKey := ed25519.NewKeyFromSeed(key)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	// Encode using Stellar StrKey format (version byte 0x30 = 'G' prefix for account ID)
	return encodeStellarStrKey(0x30, publicKey), nil //nolint:mnd
}

// encodeStellarStrKey encodes raw bytes using Stellar's StrKey format.
// StrKey = Base32(versionByte || payload || crc16_xmodem(versionByte || payload)).
func encodeStellarStrKey(version byte, payload []byte) string {
	// Build data: version byte + payload
	data := make([]byte, 0, 1+len(payload))
	data = append(data, version)
	data = append(data, payload...)

	// Calculate CRC16-XMODEM checksum
	checksum := crc16xmodem(data)
	checksumBytes := []byte{byte(checksum & 0xFF), byte(checksum >> 8)} //nolint:mnd

	// Append checksum (little-endian)
	data = append(data, checksumBytes...)

	// Encode as Base32 (no padding)
	return base32Encode(data)
}

// crc16xmodem calculates the CRC16-XMODEM checksum used by Stellar StrKey.
func crc16xmodem(data []byte) uint16 {
	crc := uint16(0x0000) //nolint:mnd
	for _, b := range data {
		crc ^= uint16(b) << 8 //nolint:mnd
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021 //nolint:mnd
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// base32Encode encodes bytes using RFC 4648 Base32 without padding.
func base32Encode(data []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	var result strings.Builder
	result.Grow((len(data)*8 + 4) / 5) //nolint:mnd

	bits := 0
	buffer := 0

	for _, b := range data {
		buffer = (buffer << 8) | int(b) //nolint:mnd
		bits += 8
		for bits >= 5 {
			bits -= 5
			result.WriteByte(alphabet[(buffer>>bits)&0x1F])
		}
	}

	// Handle remaining bits
	if bits > 0 {
		result.WriteByte(alphabet[(buffer<<(5-bits))&0x1F]) //nolint:mnd
	}

	return result.String()
}

// DeriveSuiAddress derives a Sui address from a BIP39 mnemonic.
// The function follows SLIP-0010 Ed25519 derivation with path m/44'/784'/0'/0'/0'.
// It returns an address formatted as "0x" + hex(Blake2b-256(0x00 || pubkey)).
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - address: The Sui address (starts with "0x")
//   - error: Any error that occurred during derivation
func DeriveSuiAddress(mnemonic string, bip39Passphrase string) (string, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return "", fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Derive Ed25519 key using SLIP-0010 at m/44'/784'/0'/0'/0'
	key := deriveEd25519Key(seed, []uint32{44, 784, 0, 0, 0})

	// Generate Ed25519 public key from the derived private key
	privateKey := ed25519.NewKeyFromSeed(key)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	// Sui address = Blake2b-256(flag_byte || public_key)
	// Flag byte 0x00 indicates Ed25519 scheme
	payload := make([]byte, 0, 1+len(publicKey))
	payload = append(payload, 0x00) //nolint:mnd // Ed25519 flag byte
	payload = append(payload, publicKey...)

	hash := blake2b.Sum256(payload)

	return fmt.Sprintf("0x%s", hex.EncodeToString(hash[:])), nil
}
