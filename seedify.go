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
	"fmt"

	polyseed "github.com/complex-gh/polyseed_go"
	"github.com/tyler-smith/go-bip39"
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
//
// Valid word counts are: 12, 15, 16, 18, 21, or 24.
// The entropy size is determined by the word count:
//   - 12 words = 128 bits (16 bytes) - BIP39
//   - 15 words = 160 bits (20 bytes) - BIP39
//   - 16 words = 150 bits (19 bytes) - Polyseed format
//   - 18 words = 192 bits (24 bytes) - BIP39
//   - 21 words = 224 bits (28 bytes) - BIP39
//   - 24 words = 256 bits (32 bytes) - BIP39
func ToMnemonicWithLength(key *ed25519.PrivateKey, wordCount int, seedPassphrase string) (string, error) {
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

	// Prepend word count to the seed to ensure different word counts generate
	// completely different words. We encode the word count as a uint16 (2 bytes)
	// to ensure it's properly incorporated into the entropy.
	wordCountBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(wordCountBytes, uint16(wordCount))

	// Combine word count with the seed
	prefixedSeed := make([]byte, len(wordCountBytes)+len(combinedSeed))
	copy(prefixedSeed, wordCountBytes)
	copy(prefixedSeed[len(wordCountBytes):], combinedSeed)

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
