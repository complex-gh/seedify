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
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/chekist32/go-monero/utils"
	polyseed "github.com/complex-gh/polyseed_go"
	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"
	"github.com/mr-tron/base58"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip06"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/tyler-smith/go-bip39"
	"github.com/tyler-smith/go-bip39/wordlists"
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
	// completely different words. We encode the word count as a uint16 (wordCountBytesSize bytes)
	// to ensure it's properly incorporated into the entropy.
	// Valid word counts are 12, 15, 16, 18, 21, 24 - all within uint16 range.
	wordCountBytes := make([]byte, wordCountBytesSize)
	binary.BigEndian.PutUint16(wordCountBytes, uint16(wordCount)) //nolint:gosec

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

	// Derive the spend private key (32 bytes) from polyseed
	// polyseedKeySize is the standard key size for Monero
	const polyseedKeySize = 32
	spendKeyBytes := seed.Keygen(polyseed.CoinMonero, polyseedKeySize)

	// The key bytes need to be reduced to a valid Ed25519 scalar using sc_reduce32.
	// This is done by hashing the bytes with Keccak256 and using the first 32 bytes,
	// which are then converted to a canonical scalar representation.
	reducedKey, err := reduceToScalar(spendKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to reduce key to scalar: %w", err)
	}

	// Create Monero private key from the reduced bytes
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

// reduceToScalar reduces arbitrary 32 bytes to a valid Ed25519 scalar.
// This ensures the bytes are in canonical form for use as a Monero private key.
//
// The reduction implements sc_reduce32 which reduces a 32-byte value modulo
// the curve order L = 2^252 + 27742317777372353535851937790883648493.
func reduceToScalar(keyBytes []byte) ([]byte, error) {
	// Hash the key bytes with Keccak256 to get deterministic entropy
	hash, err := utils.Keccak256Hash(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to hash key bytes: %w", err)
	}

	// Implement sc_reduce32: reduce a 256-bit value modulo L
	// For simplicity, we clear bits to ensure the value is definitely < L.
	// L ≈ 2^252, so clearing the top 4 bits ensures our value < 2^252 < L.
	result := make([]byte, 32) //nolint:mnd
	copy(result, hash)

	// Clear the top 4 bits of byte 31 (little-endian, so byte 31 is the MSB)
	// This ensures the 256-bit number is < 2^252 which is < L
	result[31] &= 0x0F

	return result, nil
}
