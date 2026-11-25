package controllers

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/servasec/appguard/backend/config"
	"github.com/servasec/appguard/backend/models"
	"github.com/servasec/appguard/backend/utils"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const repositoryHTTPTimeout = 12 * time.Second

var gitLabTokenRefreshMu sync.Mutex

type repositoryInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Path string `json:"path"`
	URL  string `json:"url"`
}

func repoPublicURL(path string) string {
	base := strings.TrimRight(os.Getenv("APPGUARD_PUBLIC_URL"), "/")
	return base + path
}

func repoStateHash(state string) string {
	sum := sha256.Sum256([]byte(state))
	return hex.EncodeToString(sum[:])
}

func externalRepositoryKey(conn models.RepositoryConnection, id string) string {
	if conn.Provider != "gitlab" {
		return id
	}
	sum := sha256.Sum256([]byte(strings.TrimRight(conn.ProviderBaseURL, "/") + "\x00" + id))
	return "gitlab:" + hex.EncodeToString(sum[:])
}

func repoRandomToken(prefix string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

func safeReturnTo(value string) string {
	if strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "//") && !strings.Contains(value, "\\") {
		return value
	}
	return "/applications"
}

func repoUserID(c *gin.Context) uint { id, _ := c.Get("user_id"); uid, _ := id.(uint); return uid }

func repoConfigured(provider string) bool {
	switch provider {
	case "github":
		return os.Getenv("REPOSITORY_GITHUB_APP_ID") != "" && os.Getenv("REPOSITORY_GITHUB_CLIENT_ID") != "" && os.Getenv("REPOSITORY_GITHUB_CLIENT_SECRET") != "" && os.Getenv("REPOSITORY_GITHUB_APP_SLUG") != "" && os.Getenv("REPOSITORY_GITHUB_PRIVATE_KEY_B64") != "" && os.Getenv("REPOSITORY_GITHUB_WEBHOOK_SECRET") != ""
	case "gitlab":
		if os.Getenv("REPOSITORY_GITLAB_CLIENT_ID") == "" || os.Getenv("REPOSITORY_GITLAB_CLIENT_SECRET") == "" || os.Getenv("APPGUARD_FEATURES_ENCRYPTION_KEY") == "" {
			return false
		}
		_, err := repoGitLabBase()
		return err == nil
	default:
		return false
	}
}

func repoGitLabBase() (string, error) {
	base := strings.TrimRight(os.Getenv("REPOSITORY_GITLAB_BASE_URL"), "/")
	if base == "" {
		base = "https://gitlab.com"
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"))) {
		return "", errors.New("invalid GitLab base URL")
	}
	return base, nil
}

func repoHTTP(ctx context.Context, method, target, bearer string, form url.Values, headers map[string]string) ([]byte, int, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, 0, err
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	client := &http.Client{Timeout: repositoryHTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	limited, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return limited, resp.StatusCode, fmt.Errorf("provider returned HTTP %d", resp.StatusCode)
	}
	return limited, resp.StatusCode, nil
}

func repositoryProviders(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"github": gin.H{"enabled": repoConfigured("github"), "permissions": "metadata:read"}, "gitlab": gin.H{"enabled": repoConfigured("gitlab"), "permissions": "read_api"}})
}

func listRepositoryConnections(c *gin.Context) {
	var connections []models.RepositoryConnection
	if err := config.DB.Where("user_id = ?", repoUserID(c)).Order("created_at desc").Find(&connections).Error; err != nil {
		c.JSON(500, gin.H{"error": "database_error"})
		return
	}
	c.JSON(200, connections)
}

func startRepositoryAuthorization(c *gin.Context) {
	provider := c.Param("provider")
	if !repoConfigured(provider) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "provider_not_configured"})
		return
	}
	state, err := repoRandomToken("")
	if err != nil {
		c.JSON(500, gin.H{"error": "state_generation_failed"})
		return
	}
	record := models.RepositoryOAuthState{UserID: repoUserID(c), Provider: provider, StateHash: repoStateHash(state), ReturnTo: safeReturnTo(c.Query("returnTo")), ExpiresAt: time.Now().Add(10 * time.Minute)}
	if err := config.DB.Create(&record).Error; err != nil {
		c.JSON(500, gin.H{"error": "database_error"})
		return
	}
	var target string
	if provider == "github" {
		target = "https://github.com/apps/" + url.PathEscape(os.Getenv("REPOSITORY_GITHUB_APP_SLUG")) + "/installations/new?state=" + url.QueryEscape(state)
	} else if provider == "gitlab" {
		base, err := repoGitLabBase()
		if err != nil {
			c.JSON(500, gin.H{"error": "invalid_provider_configuration"})
			return
		}
		q := url.Values{"client_id": {os.Getenv("REPOSITORY_GITLAB_CLIENT_ID")}, "redirect_uri": {repoPublicURL("/api/repository-connections/gitlab/callback")}, "response_type": {"code"}, "scope": {"read_api"}, "state": {state}}
		target = base + "/oauth/authorize?" + q.Encode()
	} else {
		c.JSON(404, gin.H{"error": "unsupported_provider"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"authorizationUrl": target})
}

func loadOAuthState(state, provider string, consume bool) (*models.RepositoryOAuthState, error) {
	var record models.RepositoryOAuthState
	err := config.DB.Where("state_hash = ? AND provider = ? AND expires_at > ?", repoStateHash(state), provider, time.Now()).First(&record).Error
	if err != nil {
		return nil, err
	}
	if consume {
		err = config.DB.Delete(&record).Error
	}
	return &record, err
}

func providerErrorRedirect(returnTo, message string) string {
	u := repoPublicURL(returnTo)
	parsed, err := url.Parse(u)
	if err != nil {
		return repoPublicURL("/applications")
	}
	q := parsed.Query()
	q.Set("repositoryConnectionError", message)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

func providerSuccessRedirect(returnTo, provider string) string {
	u, err := url.Parse(repoPublicURL(returnTo))
	if err != nil {
		return repoPublicURL("/applications")
	}
	q := u.Query()
	q.Set("repositoryConnection", provider)
	u.RawQuery = q.Encode()
	return u.String()
}

func githubSetupCallback(c *gin.Context) {
	state := c.Query("state")
	installationID, err := strconv.ParseInt(c.Query("installation_id"), 10, 64)
	if err != nil || installationID < 1 {
		c.JSON(400, gin.H{"error": "invalid_installation"})
		return
	}
	record, err := loadOAuthState(state, "github", false)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_or_expired_state"})
		return
	}
	if err := config.DB.Model(record).Update("installation_id", installationID).Error; err != nil {
		c.JSON(500, gin.H{"error": "database_error"})
		return
	}
	q := url.Values{"client_id": {os.Getenv("REPOSITORY_GITHUB_CLIENT_ID")}, "redirect_uri": {repoPublicURL("/api/repository-connections/github/callback")}, "state": {state}, "scope": {"read:user"}}
	c.Redirect(http.StatusFound, "https://github.com/login/oauth/authorize?"+q.Encode())
}

func exchangeOAuthCode(ctx context.Context, endpoint string, form url.Values, accept string) (map[string]any, error) {
	body, _, err := repoHTTP(ctx, http.MethodPost, endpoint, "", form, map[string]string{"Accept": accept})
	if err != nil {
		return nil, err
	}
	var result map[string]any
	err = json.Unmarshal(body, &result)
	return result, err
}

func stringField(data map[string]any, key string) string { v, _ := data[key].(string); return v }
func numericString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case float64:
		return strconv.FormatInt(int64(v), 10)
	default:
		return ""
	}
}

func githubOAuthCallback(c *gin.Context) {
	if c.Query("installation_id") != "" && c.Query("code") == "" {
		githubSetupCallback(c)
		return
	}
	state := c.Query("state")
	record, err := loadOAuthState(state, "github", false)
	if err != nil || record.InstallationID == nil {
		c.JSON(400, gin.H{"error": "invalid_or_expired_state"})
		return
	}
	redirect := safeReturnTo(record.ReturnTo)
	if c.Query("code") == "" {
		c.Redirect(302, providerErrorRedirect(redirect, "authorization_denied"))
		return
	}
	form := url.Values{"client_id": {os.Getenv("REPOSITORY_GITHUB_CLIENT_ID")}, "client_secret": {os.Getenv("REPOSITORY_GITHUB_CLIENT_SECRET")}, "code": {c.Query("code")}, "redirect_uri": {repoPublicURL("/api/repository-connections/github/callback")}}
	token, err := exchangeOAuthCode(c.Request.Context(), "https://github.com/login/oauth/access_token", form, "application/json")
	userToken := stringField(token, "access_token")
	if err != nil || userToken == "" {
		_, _ = loadOAuthState(state, "github", true)
		c.Redirect(302, providerErrorRedirect(redirect, "github_oauth_failed"))
		return
	}
	userBody, _, err := repoHTTP(c.Request.Context(), http.MethodGet, "https://api.github.com/user", userToken, nil, map[string]string{"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
	if err != nil {
		c.Redirect(302, providerErrorRedirect(redirect, "github_account_lookup_failed"))
		return
	}
	var user map[string]any
	if json.Unmarshal(userBody, &user) != nil {
		c.Redirect(302, providerErrorRedirect(redirect, "github_account_lookup_failed"))
		return
	}
	var installs struct {
		Installations []struct {
			ID      int64 `json:"id"`
			Account struct {
				Login string `json:"login"`
			} `json:"account"`
		} `json:"installations"`
	}
	var accountName string
	for page := 1; accountName == ""; page++ {
		installURL := fmt.Sprintf("https://api.github.com/user/installations?per_page=100&page=%d", page)
		installBody, _, err := repoHTTP(c.Request.Context(), http.MethodGet, installURL, userToken, nil, map[string]string{"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
		if err != nil || json.Unmarshal(installBody, &installs) != nil {
			c.Redirect(302, providerErrorRedirect(redirect, "github_installation_verification_failed"))
			return
		}
		for _, install := range installs.Installations {
			if install.ID == *record.InstallationID {
				accountName = install.Account.Login
				break
			}
		}
		if accountName != "" || len(installs.Installations) < 100 {
			break
		}
	}
	if accountName == "" {
		_, _ = loadOAuthState(state, "github", true)
		c.Redirect(302, providerErrorRedirect(redirect, "installation_not_authorized_for_user"))
		return
	}
	providerAccountID := numericString(user["id"])
	conn := models.RepositoryConnection{UserID: record.UserID, Provider: "github", ProviderAccountID: providerAccountID, AccountName: accountName, InstallationID: record.InstallationID, Status: "connected"}
	if err := config.DB.Where("user_id = ? AND provider = ? AND installation_id = ?", conn.UserID, conn.Provider, conn.InstallationID).Assign(conn).FirstOrCreate(&conn).Error; err != nil {
		c.Redirect(302, providerErrorRedirect(redirect, "connection_save_failed"))
		return
	}
	_, _ = loadOAuthState(state, "github", true)
	c.Redirect(302, providerSuccessRedirect(redirect, "github"))
}

func gitlabOAuthCallback(c *gin.Context) {
	state := c.Query("state")
	record, err := loadOAuthState(state, "gitlab", false)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_or_expired_state"})
		return
	}
	redirect := safeReturnTo(record.ReturnTo)
	if c.Query("code") == "" {
		_, _ = loadOAuthState(state, "gitlab", true)
		c.Redirect(302, providerErrorRedirect(redirect, "authorization_denied"))
		return
	}
	base, err := repoGitLabBase()
	if err != nil {
		c.Redirect(302, providerErrorRedirect(redirect, "invalid_provider_configuration"))
		return
	}
	form := url.Values{"client_id": {os.Getenv("REPOSITORY_GITLAB_CLIENT_ID")}, "client_secret": {os.Getenv("REPOSITORY_GITLAB_CLIENT_SECRET")}, "code": {c.Query("code")}, "grant_type": {"authorization_code"}, "redirect_uri": {repoPublicURL("/api/repository-connections/gitlab/callback")}}
	token, err := exchangeOAuthCode(c.Request.Context(), base+"/oauth/token", form, "application/json")
	access := stringField(token, "access_token")
	refresh := stringField(token, "refresh_token")
	if err != nil || access == "" {
		_, _ = loadOAuthState(state, "gitlab", true)
		c.Redirect(302, providerErrorRedirect(redirect, "gitlab_oauth_failed"))
		return
	}
	meBody, _, err := repoHTTP(c.Request.Context(), http.MethodGet, base+"/api/v4/user", access, nil, nil)
	var me map[string]any
	if err != nil || json.Unmarshal(meBody, &me) != nil {
		c.Redirect(302, providerErrorRedirect(redirect, "gitlab_account_lookup_failed"))
		return
	}
	key, err := utils.GetEncryptionKey()
	if err != nil {
		c.Redirect(302, providerErrorRedirect(redirect, "encryption_not_configured"))
		return
	}
	encrypted, iv, err := utils.Encrypt([]byte(access), key)
	if err != nil {
		c.Redirect(302, providerErrorRedirect(redirect, "token_encryption_failed"))
		return
	}
	refreshEncrypted, refreshIV := "", ""
	if refresh != "" {
		refreshEncrypted, refreshIV, err = utils.Encrypt([]byte(refresh), key)
		if err != nil {
			c.Redirect(302, providerErrorRedirect(redirect, "token_encryption_failed"))
			return
		}
	}
	expiresAt := time.Now().Add(time.Duration(intField(token["expires_in"], 7200)) * time.Second)
	conn := models.RepositoryConnection{UserID: record.UserID, Provider: "gitlab", ProviderAccountID: numericString(me["id"]), AccountName: stringField(me, "username"), ProviderBaseURL: base, EncryptedAccessToken: encrypted, AccessTokenIV: iv, EncryptedRefreshToken: refreshEncrypted, RefreshTokenIV: refreshIV, TokenExpiresAt: &expiresAt, Status: "connected"}
	if conn.ProviderAccountID == "" || conn.AccountName == "" {
		c.Redirect(302, providerErrorRedirect(redirect, "gitlab_account_lookup_failed"))
		return
	}
	if err := config.DB.Where("user_id = ? AND provider = ? AND provider_account_id = ?", conn.UserID, conn.Provider, conn.ProviderAccountID).Assign(conn).FirstOrCreate(&conn).Error; err != nil {
		c.Redirect(302, providerErrorRedirect(redirect, "connection_save_failed"))
		return
	}
	_ = config.DB.Model(record).Update("expires_at", time.Now()).Error
	_, _ = loadOAuthState(state, "gitlab", true)
	c.Redirect(302, providerSuccessRedirect(redirect, "gitlab"))
}

func intField(value any, fallback int64) int64 {
	switch v := value.(type) {
	case float64:
		return int64(v)
	case string:
		n, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			return n
		}
	}
	return fallback
}

func gitLabAccessToken(ctx context.Context, conn *models.RepositoryConnection) (string, error) {
	gitLabTokenRefreshMu.Lock()
	defer gitLabTokenRefreshMu.Unlock()
	key, err := utils.GetEncryptionKey()
	if err != nil {
		return "", err
	}
	access, err := utils.Decrypt(conn.EncryptedAccessToken, conn.AccessTokenIV, key)
	if err != nil {
		return "", err
	}
	if conn.TokenExpiresAt == nil || time.Until(*conn.TokenExpiresAt) > 2*time.Minute {
		return access, nil
	}
	if conn.EncryptedRefreshToken == "" {
		return "", errors.New("GitLab refresh token unavailable")
	}
	refresh, err := utils.Decrypt(conn.EncryptedRefreshToken, conn.RefreshTokenIV, key)
	if err != nil {
		return "", err
	}
	form := url.Values{"client_id": {os.Getenv("REPOSITORY_GITLAB_CLIENT_ID")}, "client_secret": {os.Getenv("REPOSITORY_GITLAB_CLIENT_SECRET")}, "grant_type": {"refresh_token"}, "refresh_token": {refresh}}
	response, err := exchangeOAuthCode(ctx, conn.ProviderBaseURL+"/oauth/token", form, "application/json")
	if err != nil {
		return "", err
	}
	nextAccess := stringField(response, "access_token")
	nextRefresh := stringField(response, "refresh_token")
	if nextAccess == "" {
		return "", errors.New("GitLab did not return a refreshed access token")
	}
	conn.EncryptedAccessToken, conn.AccessTokenIV, err = utils.Encrypt([]byte(nextAccess), key)
	if err != nil {
		return "", err
	}
	if nextRefresh != "" {
		conn.EncryptedRefreshToken, conn.RefreshTokenIV, err = utils.Encrypt([]byte(nextRefresh), key)
		if err != nil {
			return "", err
		}
	}
	expires := time.Now().Add(time.Duration(intField(response["expires_in"], 7200)) * time.Second)
	conn.TokenExpiresAt = &expires
	if err := config.DB.Model(conn).Updates(map[string]any{"encrypted_access_token": conn.EncryptedAccessToken, "access_token_iv": conn.AccessTokenIV, "encrypted_refresh_token": conn.EncryptedRefreshToken, "refresh_token_iv": conn.RefreshTokenIV, "token_expires_at": expires}).Error; err != nil {
		return "", err
	}
	return nextAccess, nil
}

func loadRepositoryConnection(c *gin.Context) (*models.RepositoryConnection, error) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		return nil, gorm.ErrRecordNotFound
	}
	var conn models.RepositoryConnection
	err = config.DB.Where("id = ? AND user_id = ?", id, repoUserID(c)).First(&conn).Error
	return &conn, err
}

func githubAppToken(ctx context.Context, installationID int64) (string, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(os.Getenv("REPOSITORY_GITHUB_PRIVATE_KEY_B64"))
	if err != nil {
		keyBytes, err = base64.RawStdEncoding.DecodeString(os.Getenv("REPOSITORY_GITHUB_PRIVATE_KEY_B64"))
	}
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return "", errors.New("invalid GitHub private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	if err != nil {
		return "", err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return "", errors.New("GitHub App key must be an RSA private key")
	}
	now := time.Now()
	claims := jwt.RegisteredClaims{Issuer: os.Getenv("REPOSITORY_GITHUB_APP_ID"), IssuedAt: jwt.NewNumericDate(now.Add(-30 * time.Second)), ExpiresAt: jwt.NewNumericDate(now.Add(8 * time.Minute))}
	appJWT, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		return "", err
	}
	body, _, err := repoHTTP(ctx, http.MethodPost, fmt.Sprintf("https://api.github.com/app/installations/%d/access_tokens", installationID), appJWT, nil, map[string]string{"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
	if err != nil {
		return "", err
	}
	var response struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &response); err != nil || response.Token == "" {
		return "", errors.New("GitHub installation token unavailable")
	}
	return response.Token, nil
}

func listConnectedRepositories(c *gin.Context) {
	conn, err := loadRepositoryConnection(c)
	if err != nil {
		c.JSON(404, gin.H{"error": "connection_not_found"})
		return
	}
	var repos []repositoryInfo
	ctx := c.Request.Context()
	if conn.Provider == "github" {
		if conn.InstallationID == nil {
			c.JSON(409, gin.H{"error": "installation_missing"})
			return
		}
		token, err := githubAppToken(ctx, *conn.InstallationID)
		if err != nil {
			c.JSON(502, gin.H{"error": "provider_authentication_failed"})
			return
		}
		for page := 1; page <= 20; page++ {
			endpoint := fmt.Sprintf("https://api.github.com/installation/repositories?per_page=100&page=%d", page)
			body, _, err := repoHTTP(ctx, http.MethodGet, endpoint, token, nil, map[string]string{"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
			if err != nil {
				c.JSON(502, gin.H{"error": "repository_list_failed"})
				return
			}
			var response struct {
				Repositories []struct {
					ID       int64  `json:"id"`
					FullName string `json:"full_name"`
					HTMLURL  string `json:"html_url"`
				} `json:"repositories"`
			}
			if json.Unmarshal(body, &response) != nil {
				c.JSON(502, gin.H{"error": "invalid_provider_response"})
				return
			}
			for _, item := range response.Repositories {
				repos = append(repos, repositoryInfo{ID: strconv.FormatInt(item.ID, 10), Name: item.FullName, Path: item.FullName, URL: item.HTMLURL})
			}
			if len(response.Repositories) < 100 {
				break
			}
		}
	} else if conn.Provider == "gitlab" {
		token, err := gitLabAccessToken(c.Request.Context(), conn)
		if err != nil {
			c.JSON(502, gin.H{"error": "provider_authentication_failed"})
			return
		}
		for page := 1; page <= 20; page++ {
			endpoint := fmt.Sprintf("%s/api/v4/projects?membership=true&simple=true&per_page=100&page=%d", conn.ProviderBaseURL, page)
			body, _, err := repoHTTP(ctx, http.MethodGet, endpoint, token, nil, nil)
			if err != nil {
				c.JSON(502, gin.H{"error": "repository_list_failed"})
				return
			}
			var items []struct {
				ID                int64  `json:"id"`
				PathWithNamespace string `json:"path_with_namespace"`
				WebURL            string `json:"web_url"`
			}
			if json.Unmarshal(body, &items) != nil {
				c.JSON(502, gin.H{"error": "invalid_provider_response"})
				return
			}
			for _, item := range items {
				repos = append(repos, repositoryInfo{ID: strconv.FormatInt(item.ID, 10), Name: item.PathWithNamespace, Path: item.PathWithNamespace, URL: item.WebURL})
			}
			if len(items) < 100 {
				break
			}
		}
	} else {
		c.JSON(400, gin.H{"error": "unsupported_provider"})
		return
	}
	c.JSON(200, repos)
}

func repositoryLink(c *gin.Context) {
	appID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_application"})
		return
	}
	var link models.ApplicationRepositoryLink
	err = config.DB.Preload("Connection").Where("application_id = ?", appID).First(&link).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		c.JSON(200, nil)
		return
	}
	if err != nil {
		c.JSON(500, gin.H{"error": "database_error"})
		return
	}
	c.JSON(200, link)
}

func createRepositoryLink(c *gin.Context) {
	appID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_application"})
		return
	}
	var req struct {
		ConnectionID uint   `json:"connectionId" binding:"required"`
		RepositoryID string `json:"repositoryId" binding:"required"`
	}
	if c.ShouldBindJSON(&req) != nil {
		c.JSON(400, gin.H{"error": "invalid_request"})
		return
	}
	var conn models.RepositoryConnection
	if err := config.DB.Where("id = ? AND user_id = ? AND status = 'connected'", req.ConnectionID, repoUserID(c)).First(&conn).Error; err != nil {
		c.JSON(404, gin.H{"error": "connection_not_found"})
		return
	}
	// Re-read the provider resource to ensure the submitted repository ID belongs to this connection.
	var repo repositoryInfo
	if conn.Provider == "github" {
		if conn.InstallationID == nil {
			c.JSON(409, gin.H{"error": "installation_missing"})
			return
		}
		token, err := githubAppToken(c.Request.Context(), *conn.InstallationID)
		if err != nil {
			c.JSON(502, gin.H{"error": "provider_authentication_failed"})
			return
		}
		if _, err := strconv.ParseInt(req.RepositoryID, 10, 64); err != nil {
			c.JSON(400, gin.H{"error": "invalid_repository_id"})
			return
		}
		endpoint := "https://api.github.com/repositories/" + url.PathEscape(req.RepositoryID)
		body, _, err := repoHTTP(c.Request.Context(), http.MethodGet, endpoint, token, nil, map[string]string{"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
		var item struct {
			ID       int64  `json:"id"`
			FullName string `json:"full_name"`
			HTMLURL  string `json:"html_url"`
		}
		if err != nil || json.Unmarshal(body, &item) != nil {
			c.JSON(502, gin.H{"error": "repository_verification_failed"})
			return
		}
		if strconv.FormatInt(item.ID, 10) == req.RepositoryID {
			repo = repositoryInfo{ID: req.RepositoryID, Name: item.FullName, Path: item.FullName, URL: item.HTMLURL}
		}
	} else if conn.Provider == "gitlab" {
		if _, err := strconv.ParseInt(req.RepositoryID, 10, 64); err != nil {
			c.JSON(400, gin.H{"error": "invalid_repository_id"})
			return
		}
		token, err := gitLabAccessToken(c.Request.Context(), &conn)
		if err != nil {
			c.JSON(502, gin.H{"error": "provider_authentication_failed"})
			return
		}
		endpoint := conn.ProviderBaseURL + "/api/v4/projects/" + url.PathEscape(req.RepositoryID)
		body, _, err := repoHTTP(c.Request.Context(), http.MethodGet, endpoint, token, nil, nil)
		var item struct {
			ID                int64  `json:"id"`
			PathWithNamespace string `json:"path_with_namespace"`
			WebURL            string `json:"web_url"`
		}
		if err == nil && json.Unmarshal(body, &item) == nil && strconv.FormatInt(item.ID, 10) == req.RepositoryID {
			repo = repositoryInfo{ID: req.RepositoryID, Name: item.PathWithNamespace, Path: item.PathWithNamespace, URL: item.WebURL}
		}
	}
	if repo.ID == "" {
		c.JSON(403, gin.H{"error": "repository_not_available_to_connection"})
		return
	}
	secret := ""
	if conn.Provider == "gitlab" {
		secret, err = repoRandomToken("gl_")
		if err != nil {
			c.JSON(500, gin.H{"error": "secret_generation_failed"})
			return
		}
	}
	secretHash := ""
	if secret != "" {
		secretHash = repoStateHash(secret)
	}
	var created models.ApplicationRepositoryLink
	err = config.DB.Transaction(func(tx *gorm.DB) error {
		var app models.Application
		if err := tx.First(&app, appID).Error; err != nil {
			return err
		}
		created = models.ApplicationRepositoryLink{ApplicationID: uint(appID), ConnectionID: conn.ID, Provider: conn.Provider, ExternalRepositoryID: externalRepositoryKey(conn, repo.ID), RepositoryPath: repo.Path, RepositoryURL: repo.URL, WebhookSecretHash: secretHash, WebhookStatus: "awaiting_delivery"}
		if err := tx.Create(&created).Error; err != nil {
			return err
		}
		return tx.Model(&app).Update("repository_url", repo.URL).Error
	})
	if err != nil {
		c.JSON(409, gin.H{"error": "repository_already_linked_or_application_unavailable"})
		return
	}
	created.Connection = conn
	c.JSON(201, gin.H{"link": created, "webhookUrl": func() string {
		if conn.Provider == "gitlab" {
			return repoPublicURL(fmt.Sprintf("/api/webhooks/gitlab/%d", created.ID))
		}
		return ""
	}(), "webhookSecret": secret})
}

func deleteRepositoryLink(c *gin.Context) {
	appID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_application"})
		return
	}
	err = config.DB.Transaction(func(tx *gorm.DB) error {
		var link models.ApplicationRepositoryLink
		if err := tx.Preload("Connection").Where("application_id = ?", appID).First(&link).Error; err != nil {
			return err
		}
		if err := tx.Delete(&link).Error; err != nil {
			return err
		}
		return tx.Model(&models.Application{}).Where("id = ? AND repository_url = ?", appID, link.RepositoryURL).Update("repository_url", "").Error
	})
	if errors.Is(err, gorm.ErrRecordNotFound) {
		c.JSON(404, gin.H{"error": "repository_link_not_found"})
		return
	}
	if err != nil {
		c.JSON(500, gin.H{"error": "database_error"})
		return
	}
	c.Status(204)
}

func disconnectRepositoryConnection(c *gin.Context) {
	conn, err := loadRepositoryConnection(c)
	if err != nil {
		c.JSON(404, gin.H{"error": "connection_not_found"})
		return
	}
	var count int64
	config.DB.Model(&models.ApplicationRepositoryLink{}).Where("connection_id = ?", conn.ID).Count(&count)
	if count > 0 {
		c.JSON(409, gin.H{"error": "remove_repository_links_first"})
		return
	}
	if err := config.DB.Delete(conn).Error; err != nil {
		c.JSON(500, gin.H{"error": "database_error"})
		return
	}
	c.Status(204)
}

func saveWebhookDelivery(tx *gorm.DB, provider, delivery, event string) (bool, error) {
	if delivery == "" {
		return false, errors.New("missing delivery identifier")
	}
	result := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&models.RepositoryWebhookDelivery{Provider: provider, DeliveryID: delivery, Event: event, ReceivedAt: time.Now()})
	return result.RowsAffected == 1, result.Error
}

func processWebhookDelivery(provider, delivery, event string, process func(*gorm.DB) error) (bool, error) {
	created := false
	err := config.DB.Transaction(func(tx *gorm.DB) error {
		var err error
		created, err = saveWebhookDelivery(tx, provider, delivery, event)
		if err != nil || !created {
			return err
		}
		if process != nil {
			return process(tx)
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return created, nil
}

func githubRepositoryWebhook(c *gin.Context) {
	secret := os.Getenv("REPOSITORY_GITHUB_WEBHOOK_SECRET")
	if secret == "" {
		c.JSON(503, gin.H{"error": "webhook_not_configured"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, (2<<20)+1))
	if err != nil || len(body) > 2<<20 {
		c.JSON(400, gin.H{"error": "invalid_payload"})
		return
	}
	provided, err := hex.DecodeString(strings.TrimPrefix(c.GetHeader("X-Hub-Signature-256"), "sha256="))
	if err != nil {
		c.JSON(401, gin.H{"error": "invalid_signature"})
		return
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	if !hmac.Equal(provided, mac.Sum(nil)) {
		c.JSON(401, gin.H{"error": "invalid_signature"})
		return
	}
	event, delivery := c.GetHeader("X-GitHub-Event"), c.GetHeader("X-GitHub-Delivery")
	if event == "" || delivery == "" {
		c.JSON(400, gin.H{"error": "missing_delivery_metadata"})
		return
	}
	var payload struct {
		Action       string `json:"action"`
		Installation struct {
			ID int64 `json:"id"`
		} `json:"installation"`
		Repository struct {
			ID int64 `json:"id"`
		} `json:"repository"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		c.JSON(400, gin.H{"error": "invalid_payload"})
		return
	}
	now := time.Now()
	created, err := processWebhookDelivery("github", delivery, event, func(tx *gorm.DB) error {
		if event == "installation" || event == "installation_repositories" {
			status := "connected"
			if payload.Action == "deleted" {
				status = "revoked"
			}
			if err := tx.Model(&models.RepositoryConnection{}).Where("provider = ? AND installation_id = ?", "github", payload.Installation.ID).Updates(map[string]any{"status": status, "last_webhook_at": now}).Error; err != nil {
				return err
			}
			if status == "revoked" {
				return tx.Model(&models.ApplicationRepositoryLink{}).
					Where("provider = ? AND connection_id IN (?)", "github", tx.Model(&models.RepositoryConnection{}).Select("id").Where("provider = ? AND installation_id = ?", "github", payload.Installation.ID)).
					Update("webhook_status", "error").Error
			}
		}
		if event == "push" && payload.Repository.ID != 0 {
			return tx.Model(&models.ApplicationRepositoryLink{}).Where("provider = ? AND external_repository_id = ?", "github", strconv.FormatInt(payload.Repository.ID, 10)).Updates(map[string]any{"webhook_status": "active", "last_webhook_at": now}).Error
		}
		return nil
	})
	if err != nil {
		c.JSON(500, gin.H{"error": "webhook_processing_failed"})
		return
	}
	if !created {
		c.JSON(200, gin.H{"received": true, "duplicate": true})
		return
	}
	c.JSON(200, gin.H{"received": true})
}

func gitlabRepositoryWebhook(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(404, gin.H{"error": "not_found"})
		return
	}
	var link models.ApplicationRepositoryLink
	if config.DB.First(&link, id).Error != nil {
		c.JSON(404, gin.H{"error": "not_found"})
		return
	}
	if link.WebhookSecretHash == "" || !hmac.Equal([]byte(repoStateHash(c.GetHeader("X-Gitlab-Token"))), []byte(link.WebhookSecretHash)) {
		c.JSON(401, gin.H{"error": "invalid_signature"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, (2<<20)+1))
	if err != nil || len(body) > 2<<20 {
		c.JSON(400, gin.H{"error": "invalid_payload"})
		return
	}
	event, delivery := c.GetHeader("X-Gitlab-Event"), c.GetHeader("X-Gitlab-Event-UUID")
	if delivery == "" {
		sum := sha256.Sum256(bytes.Join([][]byte{body, []byte(event)}, []byte{0}))
		delivery = hex.EncodeToString(sum[:])
	}
	delivery = fmt.Sprintf("%d:%s", id, delivery)
	now := time.Now()
	created, err := processWebhookDelivery("gitlab", delivery, event, func(tx *gorm.DB) error {
		if err := tx.Model(&link).Updates(map[string]any{"webhook_status": "active", "last_webhook_at": now}).Error; err != nil {
			return err
		}
		return tx.Model(&models.RepositoryConnection{}).Where("id = ?", link.ConnectionID).Update("last_webhook_at", now).Error
	})
	if err != nil {
		c.JSON(500, gin.H{"error": "webhook_processing_failed"})
		return
	}
	if !created {
		c.JSON(200, gin.H{"received": true, "duplicate": true})
		return
	}
	c.JSON(200, gin.H{"received": true})
}

func RepositoryProviders(c *gin.Context)             { repositoryProviders(c) }
func ListRepositoryConnections(c *gin.Context)       { listRepositoryConnections(c) }
func StartRepositoryAuthorization(c *gin.Context)    { startRepositoryAuthorization(c) }
func GitHubRepositoryOAuthCallback(c *gin.Context)   { githubOAuthCallback(c) }
func GitLabRepositoryOAuthCallback(c *gin.Context)   { gitlabOAuthCallback(c) }
func ListConnectedRepositories(c *gin.Context)       { listConnectedRepositories(c) }
func GetApplicationRepositoryLink(c *gin.Context)    { repositoryLink(c) }
func CreateApplicationRepositoryLink(c *gin.Context) { createRepositoryLink(c) }
func DeleteApplicationRepositoryLink(c *gin.Context) { deleteRepositoryLink(c) }
func DisconnectRepositoryConnection(c *gin.Context)  { disconnectRepositoryConnection(c) }
func GitHubRepositoryWebhook(c *gin.Context)         { githubRepositoryWebhook(c) }
func GitLabRepositoryWebhook(c *gin.Context)         { gitlabRepositoryWebhook(c) }
