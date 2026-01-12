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
	mnemonic, err := ToMnemonicWithLength(&key, 16, "", false)
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
			mnemonic, err := ToMnemonicWithLength(&key, count, "", false)
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
			_, err := ToMnemonicWithLength(&key, count, "", false)
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
	mnemonic1, err := ToMnemonicWithLength(&key, 16, "test-passphrase", false)
	is.NoErr(err)

	mnemonic2, err := ToMnemonicWithLength(&key, 16, "test-passphrase", false)
	is.NoErr(err)

	mnemonic3, err := ToMnemonicWithLength(&key, 16, "test-passphrase", false)
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
	mnemonic1, err := ToMnemonicWithLength(&key1, 16, "", false)
	is.NoErr(err)

	mnemonic2, err := ToMnemonicWithLength(&key2, 16, "", false)
	is.NoErr(err)

	is.True(mnemonic1 != mnemonic2)

	// Same key, different passphrases should produce different results
	mnemonic3, err := ToMnemonicWithLength(&key1, 16, "passphrase1", false)
	is.NoErr(err)

	mnemonic4, err := ToMnemonicWithLength(&key1, 16, "passphrase2", false)
	is.NoErr(err)

	is.True(mnemonic3 != mnemonic4)
}

// TestDeriveNostrKeys_ValidFormat tests that DeriveNostrKeys produces valid npub/nsec keys
func TestDeriveNostrKeys_ValidFormat(t *testing.T) {
	is := is.New(t)

	// Use a standard BIP39 test mnemonic
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	npub, nsec, err := DeriveNostrKeys(mnemonic, "")
	is.NoErr(err)

	// Verify format - npub should start with "npub1"
	is.True(strings.HasPrefix(npub, "npub1"))

	// Verify format - nsec should start with "nsec1"
	is.True(strings.HasPrefix(nsec, "nsec1"))

	// Verify keys are not empty
	is.True(len(npub) > 0)
	is.True(len(nsec) > 0)
}

// TestDeriveNostrKeys_Deterministic verifies that the same mnemonic always
// produces the same npub/nsec pair
func TestDeriveNostrKeys_Deterministic(t *testing.T) {
	is := is.New(t)

	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	// Derive keys multiple times
	npub1, nsec1, err := DeriveNostrKeys(mnemonic, "")
	is.NoErr(err)

	npub2, nsec2, err := DeriveNostrKeys(mnemonic, "")
	is.NoErr(err)

	npub3, nsec3, err := DeriveNostrKeys(mnemonic, "")
	is.NoErr(err)

	// All should be identical
	is.Equal(npub1, npub2)
	is.Equal(npub2, npub3)
	is.Equal(nsec1, nsec2)
	is.Equal(nsec2, nsec3)
}

// TestDeriveNostrKeys_DifferentMnemonicsProduceDifferentKeys verifies that
// different mnemonics produce different keys
func TestDeriveNostrKeys_DifferentMnemonicsProduceDifferentKeys(t *testing.T) {
	is := is.New(t)

	mnemonic1 := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	mnemonic2 := "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"

	npub1, nsec1, err := DeriveNostrKeys(mnemonic1, "")
	is.NoErr(err)

	npub2, nsec2, err := DeriveNostrKeys(mnemonic2, "")
	is.NoErr(err)

	// Different mnemonics should produce different keys
	is.True(npub1 != npub2)
	is.True(nsec1 != nsec2)
}

// TestDeriveNostrKeys_WithPassphrase tests that BIP39 passphrase affects key derivation
func TestDeriveNostrKeys_WithPassphrase(t *testing.T) {
	is := is.New(t)

	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	// Derive keys without passphrase
	npub1, nsec1, err := DeriveNostrKeys(mnemonic, "")
	is.NoErr(err)

	// Derive keys with passphrase
	npub2, nsec2, err := DeriveNostrKeys(mnemonic, "test-passphrase")
	is.NoErr(err)

	// Different passphrases should produce different keys
	is.True(npub1 != npub2)
	is.True(nsec1 != nsec2)
}

// TestDeriveNostrKeys_InvalidMnemonic tests that invalid mnemonics return errors
func TestDeriveNostrKeys_InvalidMnemonic(t *testing.T) {
	is := is.New(t)

	invalidMnemonics := []string{
		"invalid mnemonic phrase",
		"abandon abandon abandon",
		"",
		"not enough words here",
	}

	for _, mnemonic := range invalidMnemonics {
		_, _, err := DeriveNostrKeys(mnemonic, "")
		is.True(err != nil)
	}
}
