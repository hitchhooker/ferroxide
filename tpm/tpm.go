// Package tpm provides TPM 2.0 based secret sealing and unsealing.
// Secrets sealed with this package can only be recovered on the same
// machine with the same TPM state.
package tpm

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

var (
	ErrNotAvailable = errors.New("tpm: device not available")
	ErrSealFailed   = errors.New("tpm: seal operation failed")
	ErrUnsealFailed = errors.New("tpm: unseal operation failed")
)

// storage root key template per TCG spec
var srkTemplate = tpm2.TPMTPublic{
	Type:    tpm2.TPMAlgRSA,
	NameAlg: tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{
		FixedTPM:             true,
		FixedParent:          true,
		SensitiveDataOrigin:  true,
		UserWithAuth:         true,
		NoDA:                 true,
		Restricted:           true,
		Decrypt:              true,
	},
	Parameters: tpm2.NewTPMUPublicParms(
		tpm2.TPMAlgRSA,
		&tpm2.TPMSRSAParms{
			Symmetric: tpm2.TPMTSymDefObject{
				Algorithm: tpm2.TPMAlgAES,
				KeyBits: tpm2.NewTPMUSymKeyBits(
					tpm2.TPMAlgAES,
					tpm2.TPMKeyBits(128),
				),
				Mode: tpm2.NewTPMUSymMode(
					tpm2.TPMAlgAES,
					tpm2.TPMAlgCFB,
				),
			},
			KeyBits: 2048,
		},
	),
	Unique: tpm2.NewTPMUPublicID(
		tpm2.TPMAlgRSA,
		&tpm2.TPM2BPublicKeyRSA{Buffer: make([]byte, 256)},
	),
}

// sealed object template
var sealedTemplate = tpm2.TPMTPublic{
	Type:    tpm2.TPMAlgKeyedHash,
	NameAlg: tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{
		FixedTPM:     true,
		FixedParent:  true,
		UserWithAuth: true,
		NoDA:         true,
	},
	Parameters: tpm2.NewTPMUPublicParms(
		tpm2.TPMAlgKeyedHash,
		&tpm2.TPMSKeyedHashParms{
			Scheme: tpm2.TPMTKeyedHashScheme{
				Scheme: tpm2.TPMAlgNull,
			},
		},
	),
}

// IsAvailable checks if a TPM device is present on the system.
func IsAvailable() bool {
	if _, err := os.Stat("/dev/tpmrm0"); err == nil {
		return true
	}
	if _, err := os.Stat("/dev/tpm0"); err == nil {
		return true
	}
	return false
}

func openTPM() (transport.TPMCloser, error) {
	if _, err := os.Stat("/dev/tpmrm0"); err == nil {
		return linuxtpm.Open("/dev/tpmrm0")
	}
	if _, err := os.Stat("/dev/tpm0"); err == nil {
		return linuxtpm.Open("/dev/tpm0")
	}
	return nil, ErrNotAvailable
}

// Seal encrypts data using the TPM. The sealed blob can only be
// recovered on this machine using Unseal.
func Seal(data []byte) ([]byte, error) {
	if len(data) > 128 {
		return nil, fmt.Errorf("%w: data too large (max 128 bytes)", ErrSealFailed)
	}

	tpmDev, err := openTPM()
	if err != nil {
		return nil, err
	}
	defer tpmDev.Close()

	// create primary key (SRK)
	primaryCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(srkTemplate),
	}

	primaryRsp, err := primaryCmd.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("%w: create primary: %v", ErrSealFailed, err)
	}
	defer func() {
		flush := tpm2.FlushContext{FlushHandle: primaryRsp.ObjectHandle}
		flush.Execute(tpmDev)
	}()

	// generate auth value for the sealed object
	authValue := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, authValue); err != nil {
		return nil, fmt.Errorf("%w: generate auth: %v", ErrSealFailed, err)
	}

	// create sealed object
	createCmd := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryRsp.ObjectHandle,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(sealedTemplate),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{Buffer: authValue},
				Data:     tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: data}),
			},
		},
	}

	createRsp, err := createCmd.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("%w: create sealed: %v", ErrSealFailed, err)
	}

	// serialize: authValue (16) + len(private) (4) + private + public
	privBytes := createRsp.OutPrivate.Buffer
	pubBytes, err := createRsp.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("%w: serialize public: %v", ErrSealFailed, err)
	}
	pubBuf := tpm2.Marshal(pubBytes)

	result := make([]byte, 0, 16+4+len(privBytes)+len(pubBuf))
	result = append(result, authValue...)
	result = binary.LittleEndian.AppendUint32(result, uint32(len(privBytes)))
	result = append(result, privBytes...)
	result = append(result, pubBuf...)

	return result, nil
}

// Unseal recovers data previously sealed with Seal.
func Unseal(blob []byte) ([]byte, error) {
	if len(blob) < 20 { // 16 auth + 4 len minimum
		return nil, fmt.Errorf("%w: blob too short", ErrUnsealFailed)
	}

	tpmDev, err := openTPM()
	if err != nil {
		return nil, err
	}
	defer tpmDev.Close()

	// parse blob
	authValue := blob[:16]
	privLen := binary.LittleEndian.Uint32(blob[16:20])
	if len(blob) < int(20+privLen) {
		return nil, fmt.Errorf("%w: truncated blob", ErrUnsealFailed)
	}
	privBytes := blob[20 : 20+privLen]
	pubBuf := blob[20+privLen:]

	// create primary key (SRK)
	primaryCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(srkTemplate),
	}

	primaryRsp, err := primaryCmd.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("%w: create primary: %v", ErrUnsealFailed, err)
	}
	defer func() {
		flush := tpm2.FlushContext{FlushHandle: primaryRsp.ObjectHandle}
		flush.Execute(tpmDev)
	}()

	// deserialize public
	pubKey, err := tpm2.Unmarshal[tpm2.TPMTPublic](pubBuf)
	if err != nil {
		return nil, fmt.Errorf("%w: deserialize public: %v", ErrUnsealFailed, err)
	}

	// load sealed object
	loadCmd := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryRsp.ObjectHandle,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPrivate: tpm2.TPM2BPrivate{Buffer: privBytes},
		InPublic:  tpm2.New2B(*pubKey),
	}

	loadRsp, err := loadCmd.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("%w: load: %v", ErrUnsealFailed, err)
	}
	defer func() {
		flush := tpm2.FlushContext{FlushHandle: loadRsp.ObjectHandle}
		flush.Execute(tpmDev)
	}()

	// unseal
	unsealCmd := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: loadRsp.ObjectHandle,
			Auth:   tpm2.PasswordAuth(authValue),
		},
	}

	unsealRsp, err := unsealCmd.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("%w: unseal: %v", ErrUnsealFailed, err)
	}

	return unsealRsp.OutData.Buffer, nil
}
