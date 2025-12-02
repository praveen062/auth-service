package rest

import (
	"auth-service/internal/logger"
	"auth-service/internal/models"
	"auth-service/internal/service"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// MFAHandler handles MFA-related HTTP requests
type MFAHandler struct {
	mfaService service.MFAService
	logger     *logger.Logger
}

func NewMFAHandler(mfaService service.MFAService, logger *logger.Logger) *MFAHandler {
	return &MFAHandler{
		mfaService: mfaService,
		logger:     logger,
	}
}

// SetupMFA initiates MFA setup for a user (returns secret, QR code, backup codes)
func (h *MFAHandler) SetupMFA(c *gin.Context) {
	var req models.MFASetupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Failed to bind MFA setup request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": "Invalid request body"})
		return
	}

	secret, err := h.mfaService.GenerateSecret(req.UserID, req.TenantID)
	if err != nil {
		h.logger.Error("Failed to generate MFA secret", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "mfa_setup_failed", "message": "Failed to generate MFA secret"})
		return
	}

	// For demo: use email as userID (in real: fetch user email)
	qrCode, err := h.mfaService.GenerateQRCode(secret, req.UserID, "AuthService")
	if err != nil {
		h.logger.Error("Failed to generate QR code", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "mfa_setup_failed", "message": "Failed to generate QR code"})
		return
	}

	backupCodes, err := h.mfaService.GenerateBackupCodes()
	if err != nil {
		h.logger.Error("Failed to generate backup codes", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "mfa_setup_failed", "message": "Failed to generate backup codes"})
		return
	}

	// In real implementation, save secret and backup codes to DB (encrypted)
	c.JSON(http.StatusOK, models.MFASetupResponse{
		Secret:      secret,
		QRCodeURL:   "data:image/png;base64," + encodeToBase64(qrCode),
		BackupCodes: backupCodes,
		Message:     "Scan QR code with Google Authenticator or enter secret manually.",
	})
}

// VerifyMFA verifies a TOTP or backup code
func (h *MFAHandler) VerifyMFA(c *gin.Context) {
	var req models.MFAVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Failed to bind MFA verify request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": "Invalid request body"})
		return
	}

	// In real implementation, fetch secret from DB
	secret := req.Code // For demo, treat code as secret (replace with DB lookup)
	valid, err := h.mfaService.ValidateTOTP(secret, req.Code)
	if err != nil || !valid {
		h.logger.Warn("Invalid MFA code", zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_mfa_code", "message": "Invalid MFA code"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "MFA verified successfully"})
}

// Helper: encode QR code PNG to base64 string
func encodeToBase64(data []byte) string {
	// Use encoding/base64
	return "" // TODO: implement
}
