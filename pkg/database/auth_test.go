package database

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func newTestAuthStore(t *testing.T) (*AuthStore, *gorm.DB) {
	t.Helper()
	db := NewTestDB(t)
	s := NewAuthStore(db)
	require.NoError(t, s.Init())
	return s, db
}

func TestEnsureAdmin_GeneratesPasswordOnlyOnce(t *testing.T) {
	s, _ := newTestAuthStore(t)

	generated, err := s.EnsureAdmin("admin", "")
	require.NoError(t, err)
	require.NotEmpty(t, generated)

	// 用生成的密码可以登录
	acc, err := s.Authenticate("admin", generated)
	require.NoError(t, err)
	require.Equal(t, RoleAdmin, acc.Role)

	// 再次启动且未配置密码：不重置、不再生成
	again, err := s.EnsureAdmin("admin", "")
	require.NoError(t, err)
	require.Empty(t, again)
	_, err = s.Authenticate("admin", generated)
	require.NoError(t, err)
}

func TestEnsureAdmin_EnvPasswordIsSourceOfTruth(t *testing.T) {
	s, _ := newTestAuthStore(t)

	_, err := s.EnsureAdmin("admin", "first-password")
	require.NoError(t, err)
	acc, err := s.Authenticate("admin", "first-password")
	require.NoError(t, err)

	token, err := s.CreateSession(acc, time.Hour)
	require.NoError(t, err)

	// 改了环境变量重启：密码同步，旧会话作废
	_, err = s.EnsureAdmin("admin", "second-password")
	require.NoError(t, err)
	_, err = s.Authenticate("admin", "first-password")
	require.ErrorIs(t, err, ErrInvalidCredentials)
	_, err = s.Authenticate("admin", "second-password")
	require.NoError(t, err)
	_, err = s.GetSession(token)
	require.ErrorIs(t, err, ErrSessionInvalid)
}

func TestAuthenticate_RejectsBadCredentials(t *testing.T) {
	s, _ := newTestAuthStore(t)
	_, err := s.EnsureAdmin("admin", "right-password")
	require.NoError(t, err)

	_, err = s.Authenticate("admin", "wrong")
	require.ErrorIs(t, err, ErrInvalidCredentials)
	_, err = s.Authenticate("nobody", "right-password")
	require.ErrorIs(t, err, ErrInvalidCredentials)
	_, err = s.Authenticate("admin", "")
	require.ErrorIs(t, err, ErrInvalidCredentials)
}

func TestSession_Lifecycle(t *testing.T) {
	s, db := newTestAuthStore(t)
	_, err := s.EnsureAdmin("admin", "pw-123456")
	require.NoError(t, err)
	acc, err := s.Authenticate("admin", "pw-123456")
	require.NoError(t, err)

	token, err := s.CreateSession(acc, time.Hour)
	require.NoError(t, err)

	sess, err := s.GetSession(token)
	require.NoError(t, err)
	require.Equal(t, "admin", sess.Username)
	require.Equal(t, RoleAdmin, sess.Role)

	// 库里只存摘要，不存明文 token
	var count int64
	require.NoError(t, db.Model(&AuthSession{}).Where("token_hash = ?", token).Count(&count).Error)
	require.Zero(t, count)

	require.NoError(t, s.DeleteSession(token))
	_, err = s.GetSession(token)
	require.ErrorIs(t, err, ErrSessionInvalid)

	_, err = s.GetSession("")
	require.ErrorIs(t, err, ErrSessionInvalid)
	_, err = s.GetSession("not-a-real-token")
	require.ErrorIs(t, err, ErrSessionInvalid)
}

func TestSession_Expires(t *testing.T) {
	s, _ := newTestAuthStore(t)
	_, err := s.EnsureAdmin("admin", "pw-123456")
	require.NoError(t, err)
	acc, err := s.Authenticate("admin", "pw-123456")
	require.NoError(t, err)

	token, err := s.CreateSession(acc, -time.Minute)
	require.NoError(t, err)
	_, err = s.GetSession(token)
	require.ErrorIs(t, err, ErrSessionInvalid)
}

func TestAPIKey_Lifecycle(t *testing.T) {
	s, db := newTestAuthStore(t)

	key, plain, err := s.CreateAPIKey("ci", "admin", time.Now().Add(24*time.Hour))
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(plain, APIKeyPrefix))
	require.True(t, strings.HasPrefix(plain, key.Prefix))
	require.Less(t, len(key.Prefix), len(plain))

	// 明文不落库
	var stored APIKey
	require.NoError(t, db.First(&stored, "id = ?", key.ID).Error)
	require.NotEqual(t, plain, stored.KeyHash)
	require.Equal(t, HashToken(plain), stored.KeyHash)

	got, err := s.ValidateAPIKey(plain)
	require.NoError(t, err)
	require.Equal(t, key.ID, got.ID)

	// 篡改一位就不行
	_, err = s.ValidateAPIKey(plain[:len(plain)-1] + "x")
	require.ErrorIs(t, err, ErrAPIKeyInvalid)
	_, err = s.ValidateAPIKey("")
	require.ErrorIs(t, err, ErrAPIKeyInvalid)
	_, err = s.ValidateAPIKey("zhuque")
	require.ErrorIs(t, err, ErrAPIKeyInvalid)

	// 吊销后立即失效
	require.NoError(t, s.RevokeAPIKey(key.ID))
	_, err = s.ValidateAPIKey(plain)
	require.ErrorIs(t, err, ErrAPIKeyRevoked)
	require.ErrorIs(t, s.RevokeAPIKey("missing-id"), gorm.ErrRecordNotFound)
}

func TestAPIKey_RejectsPastExpiryAndExpires(t *testing.T) {
	s, db := newTestAuthStore(t)

	_, _, err := s.CreateAPIKey("bad", "admin", time.Now().Add(-time.Hour))
	require.Error(t, err)

	key, plain, err := s.CreateAPIKey("short", "admin", time.Now().Add(time.Hour))
	require.NoError(t, err)
	_, err = s.ValidateAPIKey(plain)
	require.NoError(t, err)

	// 到期后失效
	require.NoError(t, db.Model(&APIKey{}).Where("id = ?", key.ID).
		Update("expires_at", time.Now().Add(-time.Second).UnixMilli()).Error)
	_, err = s.ValidateAPIKey(plain)
	require.ErrorIs(t, err, ErrAPIKeyExpired)
}

func TestAPIKey_ListNewestFirstWithoutSecrets(t *testing.T) {
	s, _ := newTestAuthStore(t)
	_, _, err := s.CreateAPIKey("first", "admin", time.Now().Add(time.Hour))
	require.NoError(t, err)
	time.Sleep(5 * time.Millisecond)
	_, _, err = s.CreateAPIKey("second", "admin", time.Now().Add(time.Hour))
	require.NoError(t, err)

	keys, err := s.ListAPIKeys()
	require.NoError(t, err)
	require.Len(t, keys, 2)
	require.Equal(t, "second", keys[0].Name)
	require.Equal(t, "first", keys[1].Name)
}
