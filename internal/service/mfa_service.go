package service

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
)

// MFAService defines the interface for MFA operations
type MFAService interface {
	GenerateSecret(userID, tenantID string) (string, error)
	GenerateQRCode(secret, email, issuer string) ([]byte, error)
	ValidateTOTP(secret, code string) (bool, error)
	GenerateBackupCodes() ([]string, error)
}

type mfaService struct{}

func NewMFAService() MFAService {
	return &mfaService{}
}

// GenerateSecret creates a new TOTP secret for a user
func (s *mfaService) GenerateSecret(userID, tenantID string) (string, error) {
	// Generate a random base32 secret
	buf := make([]byte, 10)
	_, err := rand.Read(buf)
	if err != nil {
		return "", err
	}
	return strings.ToUpper(base32.StdEncoding.EncodeToString(buf)), nil
}

// GenerateQRCode returns a PNG QR code for Google Authenticator setup
func (s *mfaService) GenerateQRCode(secret, email, issuer string) ([]byte, error) {
	otpURL := totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: email,
		Secret:      []byte(secret),
	}
	key, err := totp.Generate(otpURL)
	if err != nil {
		return nil, err
	}
	return qrcode.Encode(key.URL(), qrcode.Medium, 256)
}

// ValidateTOTP checks if the provided code is valid for the secret
func (s *mfaService) ValidateTOTP(secret, code string) (bool, error) {
	valid, err := totp.ValidateCustom(code, secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return valid, err
}

// GenerateBackupCodes creates a set of backup codes
func (s *mfaService) GenerateBackupCodes() ([]string, error) {
	codes := make([]string, 8)
	for i := 0; i < 8; i++ {
		buf := make([]byte, 5)
		_, err := rand.Read(buf)
		if err != nil {
			return nil, err
		}
		codes[i] = fmt.Sprintf("%06d", int(buf[0])<<8|int(buf[1]))
	}
	return codes, nil
}
