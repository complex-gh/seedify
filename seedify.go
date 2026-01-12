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
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"time"

	polyseed "github.com/complex-gh/polyseed_go"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/tyler-smith/go-bip39"
	"github.com/tyler-smith/go-bip39/wordlists"
)

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

	// Special handling for 24 words: use raw seed directly
	// Skip word count prefix and hashing to ensure compatibility
	if wordCount == 24 && !brave {
		// Use the combined seed directly as entropy (32 bytes for 24 words)
		words, err := bip39.NewMnemonic(combinedSeed)
		if err != nil {
			return "", fmt.Errorf("could not create a mnemonic set of words: %w", err)
		}
		return words, nil
	}

	// Prepend word count to the seed to ensure different word counts generate
	// completely different words. We encode the word count as a uint16 (2 bytes)
	// to ensure it's properly incorporated into the entropy.
	wordCountBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(wordCountBytes, uint16(wordCount))

	// If brave flag is set, prepend the hash of "brave" (similar to word count)
	var prefixBytes []byte
	if brave {
		// Hash "brave" and take the first 2 bytes (same size as word count)
		braveHash := sha256.Sum256([]byte("brave"))
		bravePrefix := braveHash[:2]
		// Combine brave prefix with word count prefix
		prefixBytes = make([]byte, len(bravePrefix)+len(wordCountBytes))
		copy(prefixBytes, bravePrefix)
		copy(prefixBytes[len(bravePrefix):], wordCountBytes)
	} else {
		prefixBytes = wordCountBytes
	}

	// Combine prefix with the seed
	prefixedSeed := make([]byte, len(prefixBytes)+len(combinedSeed))
	copy(prefixedSeed, prefixBytes)
	copy(prefixedSeed[len(prefixBytes):], combinedSeed)

	// Special handling for 16 words - use polyseed format
	if wordCount == 16 {
		// Hash the prefixed seed to get exactly 19 bytes (150 bits) for polyseed
		// We use SHA256 and take the first 19 bytes
		hash := sha256.Sum256(prefixedSeed)
		polyseedBytes := hash[:19]

		seed, err := polyseed.CreateFromBytes(polyseedBytes, 0)
		if err != nil {
			return "", fmt.Errorf("could not create polyseed: %w", err)
		}
		defer seed.Free()

		// Get English language (index 0) for encoding
		// TODO: Support other languages based on user preference
		lang := polyseed.GetLang(0)
		if lang == nil {
			return "", fmt.Errorf("could not get polyseed language")
		}

		// Encode to mnemonic using Monero coin (default)
		mnemonic := seed.Encode(lang, polyseed.CoinMonero)

		return mnemonic, nil
	}

	// Map word count to entropy size in bytes for BIP39
	entropySizeMap := map[int]int{
		12: 16, // 128 bits
		15: 20, // 160 bits
		18: 24, // 192 bits
		21: 28, // 224 bits
		24: 32, // 256 bits
	}

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
	deltaInDays := float64(deltaInMsec) / (24 * 60 * 60 * 1000)
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
	mnemonic24, err := ToMnemonicWithLength(key, 24, seedPassphrase, true)
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

// DeriveNostrKeys derives Nostr keys (npub/nsec) from a BIP39 mnemonic phrase.
// The function converts the mnemonic to a seed, hashes it to create a deterministic
// Ed25519 private key, and then encodes the keys to npub/nsec format using bech32 encoding.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - npub: The Nostr public key in bech32 format (starts with "npub1")
//   - nsec: The Nostr private key in bech32 format (starts with "nsec1")
//   - error: Any error that occurred during derivation
//
// The function uses SHA256 to hash the full 64-byte BIP39 seed to create a
// deterministic 32-byte Ed25519 private key. This ensures the same mnemonic
// always produces the same npub/nsec pair.
func DeriveNostrKeys(mnemonic string, bip39Passphrase string) (npub string, nsec string, err error) {
	// Convert mnemonic to seed using BIP39
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return "", "", fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Hash the seed to get a deterministic 32-byte private key
	// This uses the full 64-byte seed for better entropy distribution
	hash := sha256.Sum256(seed)
	privateKeyBytes := hash[:]

	// Create Ed25519 private key from the hashed seed
	privateKey := ed25519.NewKeyFromSeed(privateKeyBytes)

	// Get the public key from the private key
	publicKey := privateKey.Public().(ed25519.PublicKey)

	// Convert keys to hex strings (Nostr uses hex-encoded keys)
	privateKeyHex := hex.EncodeToString(privateKey)
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
	// ed25519.PrivateKey is []byte, so we encode the slice directly
	privateKeyHex := hex.EncodeToString(*key)
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
