// Copyright (c) 2025-2026 complex (complex@ft.hn)
// See LICENSE for licensing information

package seedify

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/matryer/is"
)

// TestToMnemonicWithLength_Polyseed tests the 16-word polyseed format generation
func TestToMnemonicWithLength_Polyseed(t *testing.T) {
	is := is.New(t)

	// Generate a test key
	_, key, err := ed25519.GenerateKey(rand.Reader)
	is.NoErr(err)

	// Test 16-word polyseed format
	mnemonic, err := ToMnemonicWithLength(&key, 16, "")
	is.NoErr(err)
	is.True(mnemonic != "")

	// Verify it's 16 words
	words := strings.Fields(mnemonic)
	is.Equal(len(words), 16)
}

// TestToMnemonicWithLength_AllFormats tests all word count formats
func TestToMnemonicWithLength_AllFormats(t *testing.T) {
	is := is.New(t)

	// Generate a test key
	_, key, err := ed25519.GenerateKey(rand.Reader)
	is.NoErr(err)

	validCounts := []int{12, 15, 16, 18, 21, 24}

	for _, count := range validCounts {
		t.Run(string(rune(count)), func(t *testing.T) {
			is := is.New(t)
			mnemonic, err := ToMnemonicWithLength(&key, count, "")
			is.NoErr(err)
			is.True(mnemonic != "")

			words := strings.Fields(mnemonic)
			is.Equal(len(words), count)
		})
	}
}

// TestToMnemonicWithLength_InvalidWordCount tests invalid word counts
func TestToMnemonicWithLength_InvalidWordCount(t *testing.T) {
	is := is.New(t)

	// Generate a test key
	_, key, err := ed25519.GenerateKey(rand.Reader)
	is.NoErr(err)

	invalidCounts := []int{10, 11, 13, 14, 17, 19, 20, 22, 23, 25, 30}

	for _, count := range invalidCounts {
		t.Run(string(rune(count)), func(t *testing.T) {
			is := is.New(t)
			_, err := ToMnemonicWithLength(&key, count, "")
			is.True(err != nil)
		})
	}
}

// TestToMnemonicWithLength_Deterministic verifies that the same key and
// passphrase always produce the same mnemonic
func TestToMnemonicWithLength_Deterministic(t *testing.T) {
	is := is.New(t)

	// Generate a test key
	_, key, err := ed25519.GenerateKey(rand.Reader)
	is.NoErr(err)

	// Generate multiple times with same parameters
	mnemonic1, err := ToMnemonicWithLength(&key, 16, "test-passphrase")
	is.NoErr(err)

	mnemonic2, err := ToMnemonicWithLength(&key, 16, "test-passphrase")
	is.NoErr(err)

	mnemonic3, err := ToMnemonicWithLength(&key, 16, "test-passphrase")
	is.NoErr(err)

	// All should be identical
	is.Equal(mnemonic1, mnemonic2)
	is.Equal(mnemonic2, mnemonic3)
}

// TestToMnemonicWithLength_DifferentInputsProduceDifferentResults verifies
// that different keys or passphrases produce different results
func TestToMnemonicWithLength_DifferentInputsProduceDifferentResults(t *testing.T) {
	is := is.New(t)

	// Generate two different keys
	_, key1, err := ed25519.GenerateKey(rand.Reader)
	is.NoErr(err)

	_, key2, err := ed25519.GenerateKey(rand.Reader)
	is.NoErr(err)

	// Same word count, different keys should produce different results
	mnemonic1, err := ToMnemonicWithLength(&key1, 16, "")
	is.NoErr(err)

	mnemonic2, err := ToMnemonicWithLength(&key2, 16, "")
	is.NoErr(err)

	is.True(mnemonic1 != mnemonic2)

	// Same key, different passphrases should produce different results
	mnemonic3, err := ToMnemonicWithLength(&key1, 16, "passphrase1")
	is.NoErr(err)

	mnemonic4, err := ToMnemonicWithLength(&key1, 16, "passphrase2")
	is.NoErr(err)

	is.True(mnemonic3 != mnemonic4)
}
