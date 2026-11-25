package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/servasec/appguard/backend/config"
	"github.com/servasec/appguard/backend/models"
)

var (
	AccessSecret  = []byte(os.Getenv("JWT_SECRET"))
	RefreshSecret = []byte(os.Getenv("REFRESH_SECRET"))
)

func ValidateSecrets() {
	if err := validateSecrets(os.Getenv); err != nil {
		log.Fatal(err)
	}
}

func validateSecrets(getenv func(string) string) error {
	for _, name := range []string{"JWT_SECRET", "REFRESH_SECRET", "CSRF_SECRET", "APPGUARD_FEATURES_ENCRYPTION_KEY"} {
		value := getenv(name)
		if len(value) < 32 {
			return fmt.Errorf("%s must be a unique secret of at least 32 bytes (256 bits)", name)
		}
		lower := strings.ToLower(value)
		if strings.HasPrefix(value, "REPLACE_WITH_") || strings.Contains(lower, "changeme") {
			return fmt.Errorf("%s still contains an example value", name)
		}
	}
	adminPassword := getenv("APPGUARD_ADMIN_PASSWORD")
	debugMode := getenv("APPGUARD_DEBUG_ENABLED") == "true"
	if adminPassword == "" && !debugMode {
		return fmt.Errorf("APPGUARD_ADMIN_PASSWORD is required in production")
	}
	if adminPassword != "" && len(adminPassword) < 12 {
		return fmt.Errorf("APPGUARD_ADMIN_PASSWORD must be at least 12 bytes")
	}
	if adminPassword != "" && (strings.HasPrefix(adminPassword, "REPLACE_WITH_") || strings.EqualFold(adminPassword, "Admin1234!")) {
		return fmt.Errorf("APPGUARD_ADMIN_PASSWORD still contains an example value")
	}
	if len(adminPassword) > 72 {
		return fmt.Errorf("APPGUARD_ADMIN_PASSWORD must not exceed 72 bytes")
	}
	if !debugMode {
		publicURL, err := url.Parse(getenv("APPGUARD_PUBLIC_URL"))
		if err != nil || publicURL.Scheme != "https" || publicURL.Host == "" || publicURL.User != nil {
			return fmt.Errorf("APPGUARD_PUBLIC_URL must be a valid HTTPS URL in production")
		}
		if domain := getenv("APPGUARD_PUBLIC_DOMAIN"); domain == "" || !strings.EqualFold(publicURL.Hostname(), domain) {
			return fmt.Errorf("APPGUARD_PUBLIC_DOMAIN must match the HTTPS host in APPGUARD_PUBLIC_URL")
		}
	}
	return nil
}

func hashToken(tokenStr string) string {
	hash := sha256.Sum256([]byte(tokenStr))
	return hex.EncodeToString(hash[:])
}

func IsTokenBlacklisted(tokenStr string) bool {
	tokenHash := hashToken(tokenStr)
	var entry models.BlacklistedToken
	result := config.DB.Where("token_hash = ?", tokenHash).First(&entry)
	return result.Error == nil
}

func StartBlacklistCleanup() {
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			cutoff := time.Now().Add(-7 * 24 * time.Hour)
			config.DB.Where("created_at < ?", cutoff).Delete(&models.BlacklistedToken{})
		}
	}()
}

type TokenClaims struct {
	UserID uint   `json:"user_id"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

func GenerateAccessToken(userID uint, role string) (string, error) {
	claims := TokenClaims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(45 * time.Minute)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(AccessSecret)
}

func GenerateRefreshToken(userID uint) (string, error) {
	claims := jwt.RegisteredClaims{
		Subject:   strconv.Itoa(int(userID)),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(RefreshSecret)
}

func GetClaimsFromCookie(c *gin.Context) (*TokenClaims, error) {
	tokenStr, err := c.Cookie("access_token")
	if err != nil {
		return nil, err
	}

	if IsTokenBlacklisted(tokenStr) {
		return nil, jwt.ErrTokenInvalidClaims
	}

	token, err := jwt.ParseWithClaims(tokenStr, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return AccessSecret, nil
	})
	if err != nil || !token.Valid {
		return nil, err
	}

	return token.Claims.(*TokenClaims), nil
}

func BlacklistToken(tokenStr string) {
	tokenHash := hashToken(tokenStr)
	entry := models.BlacklistedToken{
		TokenHash: tokenHash,
	}
	if err := config.DB.Create(&entry).Error; err != nil {
		log.Printf("Failed to blacklist token: %v", err)
	}
}
