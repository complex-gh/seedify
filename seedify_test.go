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

// TestDeriveBitcoinAddress_ValidFormat tests that DeriveBitcoinAddress produces valid BTC addresses
func TestDeriveBitcoinAddress_ValidFormat(t *testing.T) {
	is := is.New(t)

	// Use a standard BIP39 24-word test mnemonic
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

	addr, err := DeriveBitcoinAddress(mnemonic, "")
	is.NoErr(err)

	// Verify format - P2PKH address should start with "1"
	is.True(strings.HasPrefix(addr, "1"))

	// Verify address is not empty and has reasonable length
	is.True(len(addr) >= 26)
	is.True(len(addr) <= 35)
}

// TestDeriveBitcoinAddress_Deterministic verifies that the same mnemonic always
// produces the same Bitcoin address
func TestDeriveBitcoinAddress_Deterministic(t *testing.T) {
	is := is.New(t)

	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

	// Derive address multiple times
	addr1, err := DeriveBitcoinAddress(mnemonic, "")
	is.NoErr(err)

	addr2, err := DeriveBitcoinAddress(mnemonic, "")
	is.NoErr(err)

	addr3, err := DeriveBitcoinAddress(mnemonic, "")
	is.NoErr(err)

	// All should be identical
	is.Equal(addr1, addr2)
	is.Equal(addr2, addr3)
}

// TestDeriveBitcoinAddress_DifferentMnemonicsProduceDifferentAddresses verifies that
// different mnemonics produce different addresses
func TestDeriveBitcoinAddress_DifferentMnemonicsProduceDifferentAddresses(t *testing.T) {
	is := is.New(t)

	mnemonic1 := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
	mnemonic2 := "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"

	addr1, err := DeriveBitcoinAddress(mnemonic1, "")
	is.NoErr(err)

	addr2, err := DeriveBitcoinAddress(mnemonic2, "")
	is.NoErr(err)

	// Different mnemonics should produce different addresses
	is.True(addr1 != addr2)
}

// TestDeriveEthereumAddress_ValidFormat tests that DeriveEthereumAddress produces valid ETH addresses
func TestDeriveEthereumAddress_ValidFormat(t *testing.T) {
	is := is.New(t)

	// Use a standard BIP39 24-word test mnemonic
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

	addr, err := DeriveEthereumAddress(mnemonic, "")
	is.NoErr(err)

	// Verify format - ETH address should start with "0x"
	is.True(strings.HasPrefix(addr, "0x"))

	// Verify address has correct length (42 characters including 0x prefix)
	is.Equal(len(addr), 42)
}

// TestDeriveEthereumAddress_Deterministic verifies that the same mnemonic always
// produces the same Ethereum address
func TestDeriveEthereumAddress_Deterministic(t *testing.T) {
	is := is.New(t)

	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

	// Derive address multiple times
	addr1, err := DeriveEthereumAddress(mnemonic, "")
	is.NoErr(err)

	addr2, err := DeriveEthereumAddress(mnemonic, "")
	is.NoErr(err)

	addr3, err := DeriveEthereumAddress(mnemonic, "")
	is.NoErr(err)

	// All should be identical
	is.Equal(addr1, addr2)
	is.Equal(addr2, addr3)
}

// TestDeriveEthereumAddress_DifferentMnemonicsProduceDifferentAddresses verifies that
// different mnemonics produce different addresses
func TestDeriveEthereumAddress_DifferentMnemonicsProduceDifferentAddresses(t *testing.T) {
	is := is.New(t)

	mnemonic1 := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
	mnemonic2 := "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"

	addr1, err := DeriveEthereumAddress(mnemonic1, "")
	is.NoErr(err)

	addr2, err := DeriveEthereumAddress(mnemonic2, "")
	is.NoErr(err)

	// Different mnemonics should produce different addresses
	is.True(addr1 != addr2)
}

// TestDeriveSolanaAddress_ValidFormat tests that DeriveSolanaAddress produces valid SOL addresses
func TestDeriveSolanaAddress_ValidFormat(t *testing.T) {
	is := is.New(t)

	// Use a standard BIP39 24-word test mnemonic
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

	addr, err := DeriveSolanaAddress(mnemonic, "")
	is.NoErr(err)

	// Verify address is not empty and has reasonable length (base58 encoded 32-byte public key)
	// Solana addresses are typically 32-44 characters
	is.True(len(addr) >= 32)
	is.True(len(addr) <= 44)
}

// TestDeriveSolanaAddress_Deterministic verifies that the same mnemonic always
// produces the same Solana address
func TestDeriveSolanaAddress_Deterministic(t *testing.T) {
	is := is.New(t)

	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

	// Derive address multiple times
	addr1, err := DeriveSolanaAddress(mnemonic, "")
	is.NoErr(err)

	addr2, err := DeriveSolanaAddress(mnemonic, "")
	is.NoErr(err)

	addr3, err := DeriveSolanaAddress(mnemonic, "")
	is.NoErr(err)

	// All should be identical
	is.Equal(addr1, addr2)
	is.Equal(addr2, addr3)
}

// TestDeriveSolanaAddress_DifferentMnemonicsProduceDifferentAddresses verifies that
// different mnemonics produce different addresses
func TestDeriveSolanaAddress_DifferentMnemonicsProduceDifferentAddresses(t *testing.T) {
	is := is.New(t)

	mnemonic1 := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
	mnemonic2 := "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"

	addr1, err := DeriveSolanaAddress(mnemonic1, "")
	is.NoErr(err)

	addr2, err := DeriveSolanaAddress(mnemonic2, "")
	is.NoErr(err)

	// Different mnemonics should produce different addresses
	is.True(addr1 != addr2)
}

// TestDeriveMoneroAddress_ValidFormat tests that DeriveMoneroAddress produces valid XMR addresses
func TestDeriveMoneroAddress_ValidFormat(t *testing.T) {
	is := is.New(t)

	// Generate a 16-word polyseed mnemonic from a test key
	_, key, err := ed25519.GenerateKey(rand.Reader)
	is.NoErr(err)

	mnemonic, err := ToMnemonicWithLength(&key, 16, "", false)
	is.NoErr(err)

	addr, err := DeriveMoneroAddress(mnemonic)
	is.NoErr(err)

	// Verify format - Monero mainnet primary address should start with "4"
	is.True(strings.HasPrefix(addr, "4"))

	// Verify address has correct length (95 characters)
	is.Equal(len(addr), 95)
}

// TestDeriveMoneroAddress_Deterministic verifies that the same polyseed mnemonic always
// produces the same Monero address
func TestDeriveMoneroAddress_Deterministic(t *testing.T) {
	is := is.New(t)

	// Generate a 16-word polyseed mnemonic from a test key
	_, key, err := ed25519.GenerateKey(rand.Reader)
	is.NoErr(err)

	mnemonic, err := ToMnemonicWithLength(&key, 16, "", false)
	is.NoErr(err)

	// Derive address multiple times
	addr1, err := DeriveMoneroAddress(mnemonic)
	is.NoErr(err)

	addr2, err := DeriveMoneroAddress(mnemonic)
	is.NoErr(err)

	addr3, err := DeriveMoneroAddress(mnemonic)
	is.NoErr(err)

	// All should be identical
	is.Equal(addr1, addr2)
	is.Equal(addr2, addr3)
}

// TestDeriveMoneroAddress_DifferentMnemonicsProduceDifferentAddresses verifies that
// different mnemonics produce different addresses
func TestDeriveMoneroAddress_DifferentMnemonicsProduceDifferentAddresses(t *testing.T) {
	is := is.New(t)

	// Generate two different 16-word polyseed mnemonics
	_, key1, err := ed25519.GenerateKey(rand.Reader)
	is.NoErr(err)

	_, key2, err := ed25519.GenerateKey(rand.Reader)
	is.NoErr(err)

	mnemonic1, err := ToMnemonicWithLength(&key1, 16, "", false)
	is.NoErr(err)

	mnemonic2, err := ToMnemonicWithLength(&key2, 16, "", false)
	is.NoErr(err)

	addr1, err := DeriveMoneroAddress(mnemonic1)
	is.NoErr(err)

	addr2, err := DeriveMoneroAddress(mnemonic2)
	is.NoErr(err)

	// Different mnemonics should produce different addresses
	is.True(addr1 != addr2)
}
