package websocket

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Tencent/AI-Infra-Guard/common/utils"
	"github.com/Tencent/AI-Infra-Guard/pkg/database"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const (
	// SessionCookieName 网页登录态 cookie。HttpOnly，前端 JS 读不到。
	SessionCookieName = "aig_session"
	// AgentTokenHeader Agent 与 Server 之间的内部凭据头，值来自环境变量 AIG_AGENT_TOKEN。
	AgentTokenHeader = utils.AgentTokenHeader
	// APIKeyHeader 外部接口调用携带 API Key 的请求头；也支持 Authorization: Bearer <key>。
	APIKeyHeader = "X-API-Key"

	sessionTTL = 7 * 24 * time.Hour

	// 登录失败限流：同一来源连续失败 maxLoginFailures 次后锁定 loginLockDuration。
	maxLoginFailures  = 5
	loginLockDuration = time.Minute

	principalContextKey = "auth_principal"
	maxAPIKeyNameLen    = 128
)

// 认证主体类型。
const (
	PrincipalSession = "session" // 网页登录用户
	PrincipalAPIKey  = "apikey"  // 外部 API Key
	PrincipalAgent   = "agent"   // 内部 Agent
)

// Principal 描述通过认证的调用方。
type Principal struct {
	Kind     string
	Username string
	Role     string
	KeyID    string
}

// Authenticator 负责登录、会话与 API Key 校验。
type Authenticator struct {
	store      *database.AuthStore
	agentToken string
	limiter    *loginLimiter
}

// NewAuthenticator 创建认证器。agentToken 为空时，Agent 内部凭据一律不通过。
func NewAuthenticator(store *database.AuthStore, agentToken string) *Authenticator {
	return &Authenticator{store: store, agentToken: agentToken, limiter: newLoginLimiter()}
}

func unauthorized(c *gin.Context, code, message string) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"status":  http.StatusUnauthorized,
		"code":    code,
		"message": message,
	})
}

func forbidden(c *gin.Context, message string) {
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
		"status":  http.StatusForbidden,
		"code":    "forbidden",
		"message": message,
	})
}

// GetPrincipal 取出当前请求的认证主体。
func GetPrincipal(c *gin.Context) *Principal {
	if v, ok := c.Get(principalContextKey); ok {
		if p, ok := v.(*Principal); ok {
			return p
		}
	}
	return nil
}

// apiKeyFromRequest 从请求头取 API Key。不支持放在 URL 里，避免写进访问日志。
func apiKeyFromRequest(c *gin.Context) string {
	if v := strings.TrimSpace(c.GetHeader(APIKeyHeader)); v != "" {
		return v
	}
	if auth := c.GetHeader("Authorization"); len(auth) > 7 && strings.EqualFold(auth[:7], "Bearer ") {
		if v := strings.TrimSpace(auth[7:]); strings.HasPrefix(v, database.APIKeyPrefix) {
			return v
		}
	}
	return ""
}

// agentAllowed 限定内部 Agent 凭据只能访问 Agent 实际用到的接口，
// 即使 AIG_AGENT_TOKEN 泄漏，也不能用它管理模型、删任务等。
func agentAllowed(c *gin.Context) bool {
	fp := c.FullPath()
	switch {
	case fp == "/api/v1/agents/ws":
		return true
	case c.Request.Method == http.MethodPost && fp == "/api/v1/app/tasks/:sessionId/downloadFile":
		return true
	case c.Request.Method == http.MethodPost && fp == "/api/v1/app/tasks/uploadFile":
		return true
	case c.Request.Method == http.MethodGet && strings.HasPrefix(fp, "/api/v1/knowledge/"):
		return true
	}
	return false
}

// Authenticate 是鉴权中间件：网页登录态、API Key、Agent 内部凭据三者任一通过即放行。
func (a *Authenticator) Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. 网页登录态（cookie）
		if token, err := c.Cookie(SessionCookieName); err == nil && token != "" {
			if sess, err := a.store.GetSession(token); err == nil {
				c.Set(principalContextKey, &Principal{Kind: PrincipalSession, Username: sess.Username, Role: sess.Role})
				c.Next()
				return
			} else if !errors.Is(err, database.ErrSessionInvalid) {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"status": 500, "message": "internal error"})
				return
			}
		}

		// 2. 外部接口 API Key
		if plain := apiKeyFromRequest(c); plain != "" {
			key, err := a.store.ValidateAPIKey(plain)
			switch {
			case err == nil:
				c.Set(principalContextKey, &Principal{Kind: PrincipalAPIKey, Username: "api:" + key.Name, KeyID: key.ID})
				c.Next()
			case errors.Is(err, database.ErrAPIKeyExpired):
				unauthorized(c, "api_key_expired", "API key has expired")
			case errors.Is(err, database.ErrAPIKeyRevoked):
				unauthorized(c, "api_key_revoked", "API key has been revoked")
			case errors.Is(err, database.ErrAPIKeyInvalid):
				unauthorized(c, "invalid_api_key", "invalid API key")
			default:
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"status": 500, "message": "internal error"})
			}
			return
		}

		// 3. Agent 内部凭据
		if got := c.GetHeader(AgentTokenHeader); got != "" && a.agentToken != "" &&
			subtle.ConstantTimeCompare([]byte(got), []byte(a.agentToken)) == 1 {
			if !agentAllowed(c) {
				forbidden(c, "agent credential is not allowed for this endpoint")
				return
			}
			c.Set(principalContextKey, &Principal{Kind: PrincipalAgent, Username: "agent"})
			c.Next()
			return
		}

		unauthorized(c, "unauthorized", "authentication required: log in, or pass a valid API key in the X-API-Key header")
	}
}

// RequireAdminSession 只允许 admin 通过网页登录态访问。API Key 不能用来管理 API Key。
func (a *Authenticator) RequireAdminSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		p := GetPrincipal(c)
		if p == nil || p.Kind != PrincipalSession || p.Role != database.RoleAdmin {
			forbidden(c, "admin login required")
			return
		}
		c.Next()
	}
}

func isSecureRequest(c *gin.Context) bool {
	return c.Request.TLS != nil || strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https")
}

func setSessionCookie(c *gin.Context, token string, maxAge int) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   isSecureRequest(c),
		SameSite: http.SameSiteLaxMode,
	})
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// HandleLogin POST /api/v1/auth/login
func (a *Authenticator) HandleLogin(c *gin.Context) {
	ip := c.ClientIP()
	if wait := a.limiter.lockedFor(ip); wait > 0 {
		c.Header("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		c.JSON(http.StatusTooManyRequests, gin.H{
			"status":  http.StatusTooManyRequests,
			"code":    "too_many_attempts",
			"message": "too many failed attempts, try again later",
		})
		return
	}

	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": 400, "message": "invalid request"})
		return
	}
	req.Username = strings.TrimSpace(req.Username)

	acc, err := a.store.Authenticate(req.Username, req.Password)
	if err != nil {
		if errors.Is(err, database.ErrInvalidCredentials) {
			a.limiter.fail(ip)
			c.JSON(http.StatusUnauthorized, gin.H{
				"status":  http.StatusUnauthorized,
				"code":    "invalid_credentials",
				"message": "invalid username or password",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"status": 500, "message": "internal error"})
		return
	}
	a.limiter.reset(ip)

	token, err := a.store.CreateSession(acc, sessionTTL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 500, "message": "internal error"})
		return
	}
	setSessionCookie(c, token, int(sessionTTL.Seconds()))
	c.JSON(http.StatusOK, gin.H{
		"status":  0,
		"message": "success",
		"data":    gin.H{"username": acc.Username, "role": acc.Role},
	})
}

// HandleLogout POST /api/v1/auth/logout
func (a *Authenticator) HandleLogout(c *gin.Context) {
	if token, err := c.Cookie(SessionCookieName); err == nil {
		_ = a.store.DeleteSession(token)
	}
	setSessionCookie(c, "", -1)
	c.JSON(http.StatusOK, gin.H{"status": 0, "message": "success"})
}

// HandleMe GET /api/v1/auth/me，前端用它判断是否已登录以及是否为 admin。
func (a *Authenticator) HandleMe(c *gin.Context) {
	p := GetPrincipal(c)
	c.JSON(http.StatusOK, gin.H{
		"status":  0,
		"message": "success",
		"data":    gin.H{"username": p.Username, "role": p.Role, "auth_type": p.Kind},
	})
}

type createAPIKeyRequest struct {
	Name string `json:"name"`
	// ExpiresAt 到期时间，Unix 毫秒时间戳或 RFC3339 字符串。
	ExpiresAt any `json:"expires_at"`
	// ExpiresInDays 从现在起多少天后到期；与 ExpiresAt 二选一。
	ExpiresInDays int `json:"expires_in_days"`
}

func parseExpiry(req *createAPIKeyRequest, now time.Time) (time.Time, bool) {
	switch v := req.ExpiresAt.(type) {
	case float64:
		if v > 0 {
			return time.UnixMilli(int64(v)), true
		}
	case string:
		if v = strings.TrimSpace(v); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				return t, true
			}
			if t, err := time.ParseInLocation("2006-01-02", v, time.Local); err == nil {
				// 只给了日期：当天结束前有效
				return t.Add(24*time.Hour - time.Second), true
			}
			return time.Time{}, false
		}
	}
	if req.ExpiresInDays > 0 {
		return now.AddDate(0, 0, req.ExpiresInDays), true
	}
	return time.Time{}, false
}

// HandleCreateAPIKey POST /api/v1/auth/api-keys（仅 admin）
func (a *Authenticator) HandleCreateAPIKey(c *gin.Context) {
	var req createAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": 400, "message": "invalid request"})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > maxAPIKeyNameLen {
		c.JSON(http.StatusBadRequest, gin.H{"status": 400, "code": "invalid_name", "message": "name is required (max 128 characters)"})
		return
	}
	now := time.Now()
	expiresAt, ok := parseExpiry(&req, now)
	if !ok || !expiresAt.After(now) {
		c.JSON(http.StatusBadRequest, gin.H{"status": 400, "code": "invalid_expiry", "message": "a future expiry time is required"})
		return
	}

	key, plain, err := a.store.CreateAPIKey(req.Name, GetPrincipal(c).Username, expiresAt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 500, "message": "internal error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":  0,
		"message": "success",
		// api_key 明文只在这一次返回，之后无法再查看
		"data": gin.H{"api_key": plain, "key": key},
	})
}

// HandleListAPIKeys GET /api/v1/auth/api-keys（仅 admin）
func (a *Authenticator) HandleListAPIKeys(c *gin.Context) {
	keys, err := a.store.ListAPIKeys()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 500, "message": "internal error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": 0, "message": "success", "data": gin.H{"items": keys, "total": len(keys)}})
}

// HandleRevokeAPIKey DELETE /api/v1/auth/api-keys/:id（仅 admin）
func (a *Authenticator) HandleRevokeAPIKey(c *gin.Context) {
	err := a.store.RevokeAPIKey(c.Param("id"))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"status": 404, "message": "api key not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"status": 500, "message": "internal error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": 0, "message": "success"})
}

// loginLimiter 按来源 IP 限制连续登录失败次数。
type loginLimiter struct {
	mu      sync.Mutex
	entries map[string]*loginEntry
}

type loginEntry struct {
	fails       int
	lockedUntil time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{entries: make(map[string]*loginEntry)}
}

// lockedFor 返回还需等待多久，未被锁定返回 0。
func (l *loginLimiter) lockedFor(ip string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e, ok := l.entries[ip]; ok {
		if wait := time.Until(e.lockedUntil); wait > 0 {
			return wait
		}
	}
	return 0
}

func (l *loginLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[ip]
	if !ok {
		e = &loginEntry{}
		l.entries[ip] = e
	}
	// 上一轮锁定已过，重新计数
	if !e.lockedUntil.IsZero() && time.Now().After(e.lockedUntil) {
		e.fails = 0
		e.lockedUntil = time.Time{}
	}
	e.fails++
	if e.fails >= maxLoginFailures {
		e.lockedUntil = time.Now().Add(loginLockDuration)
	}
	// 防止 map 无限增长
	if len(l.entries) > 10000 {
		now := time.Now()
		for k, v := range l.entries {
			if v.lockedUntil.Before(now) && k != ip {
				delete(l.entries, k)
			}
		}
	}
}

func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, ip)
}
