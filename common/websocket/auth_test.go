package websocket

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Tencent/AI-Infra-Guard/pkg/database"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

const testAgentToken = "test-agent-token"

type authFixture struct {
	router *gin.Engine
	db     *gorm.DB
	store  *database.AuthStore
}

// newAuthFixture 搭一个与 server.go 相同结构的路由：
// login/logout 公开，其余走 Authenticate，API Key 管理要求 admin 登录态。
func newAuthFixture(t *testing.T) *authFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db := database.NewTestDB(t)

	store := database.NewAuthStore(db)
	require.NoError(t, store.Init())
	_, err := store.EnsureAdmin("admin", "admin-pass-123")
	require.NoError(t, err)

	auth := NewAuthenticator(store, testAgentToken)
	r := gin.New()
	v1 := r.Group("/api/v1")
	v1.POST("/auth/login", auth.HandleLogin)
	v1.POST("/auth/logout", auth.HandleLogout)
	v1.Use(auth.Authenticate())
	{
		v1.GET("/auth/me", auth.HandleMe)
		keys := v1.Group("/auth/api-keys", auth.RequireAdminSession())
		keys.GET("", auth.HandleListAPIKeys)
		keys.POST("", auth.HandleCreateAPIKey)
		keys.DELETE("/:id", auth.HandleRevokeAPIKey)

		// 模拟业务接口
		v1.GET("/app/models", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })
		v1.POST("/app/tasks/uploadFile", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })
		v1.GET("/knowledge/fingerprints", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })
		v1.GET("/agents/ws", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })
		v1.DELETE("/app/models", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })
	}
	return &authFixture{router: r, db: db, store: store}
}

func (f *authFixture) do(method, path, body string, headers map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	var rd *bytes.Reader
	if body != "" {
		rd = bytes.NewReader([]byte(body))
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	req.RemoteAddr = "10.0.0.1:1234"
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

func (f *authFixture) login(t *testing.T) *http.Cookie {
	t.Helper()
	w := f.do("POST", "/api/v1/auth/login", `{"username":"admin","password":"admin-pass-123"}`, nil)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	for _, c := range w.Result().Cookies() {
		if c.Name == SessionCookieName {
			return c
		}
	}
	t.Fatal("login did not set session cookie")
	return nil
}

func (f *authFixture) createKey(t *testing.T, cookie *http.Cookie, body string) (id, plain string) {
	t.Helper()
	w := f.do("POST", "/api/v1/auth/api-keys", body, nil, cookie)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp struct {
		Data struct {
			APIKey string `json:"api_key"`
			Key    struct {
				ID string `json:"id"`
			} `json:"key"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.Data.APIKey)
	return resp.Data.Key.ID, resp.Data.APIKey
}

func TestAuth_NoCredentialsRejected(t *testing.T) {
	f := newAuthFixture(t)
	for _, tc := range []struct{ method, path string }{
		{"GET", "/api/v1/app/models"},
		{"POST", "/api/v1/app/tasks/uploadFile"},
		{"GET", "/api/v1/auth/me"},
		{"GET", "/api/v1/auth/api-keys"},
		{"GET", "/api/v1/agents/ws"},
	} {
		w := f.do(tc.method, tc.path, "", nil)
		require.Equal(t, http.StatusUnauthorized, w.Code, "%s %s", tc.method, tc.path)
	}
}

func TestAuth_LoginFlow(t *testing.T) {
	f := newAuthFixture(t)

	// 错误密码
	w := f.do("POST", "/api/v1/auth/login", `{"username":"admin","password":"nope"}`, nil)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Empty(t, w.Result().Cookies())

	cookie := f.login(t)
	require.True(t, cookie.HttpOnly)
	require.Equal(t, http.SameSiteLaxMode, cookie.SameSite)

	// 登录后网页无需 API Key 即可访问业务接口
	require.Equal(t, http.StatusOK, f.do("GET", "/api/v1/app/models", "", nil, cookie).Code)

	w = f.do("GET", "/api/v1/auth/me", "", nil, cookie)
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), `"role":"admin"`)

	// 退出后 cookie 作废
	require.Equal(t, http.StatusOK, f.do("POST", "/api/v1/auth/logout", "", nil, cookie).Code)
	require.Equal(t, http.StatusUnauthorized, f.do("GET", "/api/v1/app/models", "", nil, cookie).Code)
}

func TestAuth_LoginRateLimit(t *testing.T) {
	f := newAuthFixture(t)
	for i := 0; i < maxLoginFailures; i++ {
		w := f.do("POST", "/api/v1/auth/login", `{"username":"admin","password":"bad"}`, nil)
		require.Equal(t, http.StatusUnauthorized, w.Code)
	}
	// 锁定期内，连正确密码也被拒
	w := f.do("POST", "/api/v1/auth/login", `{"username":"admin","password":"admin-pass-123"}`, nil)
	require.Equal(t, http.StatusTooManyRequests, w.Code)
	require.NotEmpty(t, w.Header().Get("Retry-After"))
}

func TestAuth_ForgedSessionCookieRejected(t *testing.T) {
	f := newAuthFixture(t)
	w := f.do("GET", "/api/v1/app/models", "", nil, &http.Cookie{Name: SessionCookieName, Value: "deadbeef"})
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuth_APIKeyHeaderAndBearer(t *testing.T) {
	f := newAuthFixture(t)
	cookie := f.login(t)
	_, plain := f.createKey(t, cookie, `{"name":"ci","expires_in_days":30}`)

	// 不带 key：拒绝
	require.Equal(t, http.StatusUnauthorized, f.do("GET", "/api/v1/app/models", "", nil).Code)
	// X-API-Key
	require.Equal(t, http.StatusOK, f.do("GET", "/api/v1/app/models", "", map[string]string{"X-API-Key": plain}).Code)
	// Authorization: Bearer
	require.Equal(t, http.StatusOK, f.do("GET", "/api/v1/app/models", "", map[string]string{"Authorization": "Bearer " + plain}).Code)
	// 错误的 key
	w := f.do("GET", "/api/v1/app/models", "", map[string]string{"X-API-Key": plain + "x"})
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Contains(t, w.Body.String(), "invalid_api_key")
}

func TestAuth_APIKeyExpiredAndRevoked(t *testing.T) {
	f := newAuthFixture(t)
	cookie := f.login(t)

	id, plain := f.createKey(t, cookie, `{"name":"temp","expires_in_days":1}`)
	hdr := map[string]string{"X-API-Key": plain}
	require.Equal(t, http.StatusOK, f.do("GET", "/api/v1/app/models", "", hdr).Code)

	// 到期
	require.NoError(t, f.db.Model(&database.APIKey{}).Where("id = ?", id).
		Update("expires_at", time.Now().Add(-time.Second).UnixMilli()).Error)
	w := f.do("GET", "/api/v1/app/models", "", hdr)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Contains(t, w.Body.String(), "api_key_expired")

	// 吊销
	id2, plain2 := f.createKey(t, cookie, `{"name":"temp2","expires_in_days":1}`)
	hdr2 := map[string]string{"X-API-Key": plain2}
	require.Equal(t, http.StatusOK, f.do("GET", "/api/v1/app/models", "", hdr2).Code)
	require.Equal(t, http.StatusOK, f.do("DELETE", "/api/v1/auth/api-keys/"+id2, "", nil, cookie).Code)
	w = f.do("GET", "/api/v1/app/models", "", hdr2)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Contains(t, w.Body.String(), "api_key_revoked")
}

func TestAuth_APIKeyCannotManageAPIKeys(t *testing.T) {
	f := newAuthFixture(t)
	cookie := f.login(t)
	_, plain := f.createKey(t, cookie, `{"name":"ci","expires_in_days":30}`)
	hdr := map[string]string{"X-API-Key": plain}

	require.Equal(t, http.StatusForbidden, f.do("GET", "/api/v1/auth/api-keys", "", hdr).Code)
	require.Equal(t, http.StatusForbidden,
		f.do("POST", "/api/v1/auth/api-keys", `{"name":"x","expires_in_days":1}`, hdr).Code)
}

func TestAuth_CreateAPIKeyValidation(t *testing.T) {
	f := newAuthFixture(t)
	cookie := f.login(t)

	for name, body := range map[string]string{
		"missing name":    `{"expires_in_days":7}`,
		"blank name":      `{"name":"  ","expires_in_days":7}`,
		"no expiry":       `{"name":"a"}`,
		"past timestamp":  `{"name":"a","expires_at":1000}`,
		"past rfc3339":    `{"name":"a","expires_at":"2000-01-01T00:00:00Z"}`,
		"garbage expiry":  `{"name":"a","expires_at":"tomorrow"}`,
		"too long name":   `{"name":"` + strings.Repeat("a", 200) + `","expires_in_days":7}`,
		"negative days":   `{"name":"a","expires_in_days":-3}`,
		"not json":        `nope`,
	} {
		w := f.do("POST", "/api/v1/auth/api-keys", body, nil, cookie)
		require.Equal(t, http.StatusBadRequest, w.Code, name)
	}

	// 合法写法：毫秒时间戳 / RFC3339 / 天数
	future := time.Now().Add(48 * time.Hour)
	for name, body := range map[string]string{
		"unix ms": `{"name":"a","expires_at":` + itoa64(future.UnixMilli()) + `}`,
		"rfc3339": `{"name":"b","expires_at":"` + future.Format(time.RFC3339) + `"}`,
		"days":    `{"name":"c","expires_in_days":5}`,
	} {
		w := f.do("POST", "/api/v1/auth/api-keys", body, nil, cookie)
		require.Equal(t, http.StatusOK, w.Code, "%s: %s", name, w.Body.String())
	}
}

func itoa64(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestAuth_ListNeverExposesSecrets(t *testing.T) {
	f := newAuthFixture(t)
	cookie := f.login(t)
	_, plain := f.createKey(t, cookie, `{"name":"ci","expires_in_days":30}`)

	w := f.do("GET", "/api/v1/auth/api-keys", "", nil, cookie)
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	require.NotContains(t, body, plain)
	require.NotContains(t, body, "key_hash")
	require.Contains(t, body, `"name":"ci"`)
}

func TestAuth_AgentTokenScopedToAgentEndpoints(t *testing.T) {
	f := newAuthFixture(t)
	hdr := map[string]string{AgentTokenHeader: testAgentToken}

	// Agent 实际用到的接口：放行
	require.Equal(t, http.StatusOK, f.do("GET", "/api/v1/agents/ws", "", hdr).Code)
	require.Equal(t, http.StatusOK, f.do("POST", "/api/v1/app/tasks/uploadFile", "", hdr).Code)
	require.Equal(t, http.StatusOK, f.do("GET", "/api/v1/knowledge/fingerprints", "", hdr).Code)

	// 其他接口：即使凭据泄漏也不能用
	require.Equal(t, http.StatusForbidden, f.do("GET", "/api/v1/app/models", "", hdr).Code)
	require.Equal(t, http.StatusForbidden, f.do("DELETE", "/api/v1/app/models", "", hdr).Code)
	require.Equal(t, http.StatusForbidden, f.do("GET", "/api/v1/auth/api-keys", "", hdr).Code)

	// 错误的凭据
	bad := map[string]string{AgentTokenHeader: "wrong"}
	require.Equal(t, http.StatusUnauthorized, f.do("GET", "/api/v1/agents/ws", "", bad).Code)
	// 旧版本写死的 X-APIKey: zhuque 不再有效
	legacy := map[string]string{"X-APIKey": "zhuque"}
	require.Equal(t, http.StatusUnauthorized, f.do("GET", "/api/v1/agents/ws", "", legacy).Code)
}

func TestAuth_EmptyAgentTokenNeverMatches(t *testing.T) {
	f := newAuthFixture(t)
	// 服务端未配置 agent token 时，空头/任意头都不应通过
	auth := NewAuthenticator(f.store, "")
	r := gin.New()
	r.Use(auth.Authenticate())
	r.GET("/api/v1/agents/ws", func(c *gin.Context) { c.Status(200) })

	for _, h := range []string{"", "anything"} {
		req := httptest.NewRequest("GET", "/api/v1/agents/ws", nil)
		if h != "" {
			req.Header.Set(AgentTokenHeader, h)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		require.Equal(t, http.StatusUnauthorized, w.Code)
	}
}
