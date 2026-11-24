package database

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

const (
	// RoleAdmin 管理员角色，只有管理员才能管理 API Key。
	RoleAdmin = "admin"

	// APIKeyPrefix 是所有 API Key 的固定前缀，便于识别和在日志/代码扫描中发现泄漏。
	APIKeyPrefix = "aig_"

	// apiKeyLastUsedThrottle 限制 last_used_at 的写入频率，避免每个请求都写一次数据库。
	apiKeyLastUsedThrottle = time.Minute
)

var (
	// ErrInvalidCredentials 用户名或密码错误。
	ErrInvalidCredentials = errors.New("invalid username or password")
	// ErrSessionInvalid 登录会话不存在或已过期。
	ErrSessionInvalid = errors.New("session invalid or expired")
	// ErrAPIKeyInvalid API Key 不存在。
	ErrAPIKeyInvalid = errors.New("api key invalid")
	// ErrAPIKeyExpired API Key 已过期。
	ErrAPIKeyExpired = errors.New("api key expired")
	// ErrAPIKeyRevoked API Key 已被吊销。
	ErrAPIKeyRevoked = errors.New("api key revoked")
)

// AuthAccount 登录账号。与 users 表（任务数据归属）相互独立。
type AuthAccount struct {
	ID           uint   `gorm:"primaryKey" json:"id"`
	Username     string `gorm:"column:username;size:64;not null;uniqueIndex" json:"username"`
	PasswordHash string `gorm:"column:password_hash;not null" json:"-"`
	Role         string `gorm:"column:role;size:16;not null;default:'admin'" json:"role"`
	CreatedAt    int64  `gorm:"column:created_at;not null" json:"created_at"`
	UpdatedAt    int64  `gorm:"column:updated_at;not null" json:"updated_at"`
}

// TableName 指定表名。
func (AuthAccount) TableName() string { return "auth_accounts" }

// AuthSession 网页登录会话。只保存 token 的 SHA-256，数据库泄漏也无法直接冒用。
type AuthSession struct {
	TokenHash string `gorm:"column:token_hash;primaryKey;size:64" json:"-"`
	Username  string `gorm:"column:username;size:64;not null" json:"username"`
	Role      string `gorm:"column:role;size:16;not null" json:"role"`
	ExpiresAt int64  `gorm:"column:expires_at;not null;index" json:"expires_at"`
	CreatedAt int64  `gorm:"column:created_at;not null" json:"created_at"`
}

// TableName 指定表名。
func (AuthSession) TableName() string { return "auth_sessions" }

// APIKey 供外部接口调用的密钥。明文只在创建时返回一次，库里只存 SHA-256。
type APIKey struct {
	ID         string `gorm:"column:id;primaryKey;size:36" json:"id"`
	Name       string `gorm:"column:name;size:128;not null" json:"name"`
	KeyHash    string `gorm:"column:key_hash;size:64;not null;uniqueIndex" json:"-"`
	Prefix     string `gorm:"column:prefix;size:24;not null" json:"prefix"` // 用于列表中辨认，如 aig_AbCd1234
	CreatedBy  string `gorm:"column:created_by;size:64;not null" json:"created_by"`
	CreatedAt  int64  `gorm:"column:created_at;not null" json:"created_at"`
	ExpiresAt  int64  `gorm:"column:expires_at;not null;index" json:"expires_at"`
	Revoked    bool   `gorm:"column:revoked;not null;default:false" json:"revoked"`
	LastUsedAt int64  `gorm:"column:last_used_at;not null;default:0" json:"last_used_at"`
}

// TableName 指定表名。
func (APIKey) TableName() string { return "api_keys" }

// AuthStore 认证相关数据存储。
type AuthStore struct {
	db *gorm.DB
}

// NewAuthStore 创建 AuthStore。
func NewAuthStore(db *gorm.DB) *AuthStore {
	return &AuthStore{db: db}
}

// Init 迁移认证相关表结构。
func (s *AuthStore) Init() error {
	return s.db.AutoMigrate(&AuthAccount{}, &AuthSession{}, &APIKey{})
}

// HashToken 计算 token / API Key 的存储摘要。
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// randomString 生成 n 位字母数字随机串。
func randomString(n int) (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
	out := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := range out {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = alphabet[idx.Int64()]
	}
	return string(out), nil
}

// EnsureAdmin 保证管理员账号存在。
//
//   - password 非空：账号不存在则创建；已存在但密码不一致则同步为该密码
//     （即环境变量 AIG_ADMIN_PASSWORD 是密码的唯一来源，改环境变量重启即可重置）。
//   - password 为空：账号不存在才创建，并生成随机密码返回（只在创建当次可见）；
//     已存在则不改动。
func (s *AuthStore) EnsureAdmin(username, password string) (generated string, err error) {
	var acc AuthAccount
	// 用 Limit(1).Find 而不是 First：查不到是正常情况，不要让 GORM 打 "record not found" 日志
	res := s.db.Where("username = ?", username).Limit(1).Find(&acc)
	if res.Error != nil {
		return "", res.Error
	}
	exists := res.RowsAffected > 0

	if password == "" {
		if exists {
			return "", nil
		}
		password, err = randomString(18)
		if err != nil {
			return "", err
		}
		generated = password
	}

	now := time.Now().UnixMilli()
	if !exists {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return "", err
		}
		return generated, s.db.Create(&AuthAccount{
			Username:     username,
			PasswordHash: string(hash),
			Role:         RoleAdmin,
			CreatedAt:    now,
			UpdatedAt:    now,
		}).Error
	}

	if bcrypt.CompareHashAndPassword([]byte(acc.PasswordHash), []byte(password)) == nil {
		return "", nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	if err := s.db.Model(&AuthAccount{}).Where("id = ?", acc.ID).Updates(map[string]interface{}{
		"password_hash": string(hash),
		"updated_at":    now,
	}).Error; err != nil {
		return "", err
	}
	// 密码被重置，旧会话全部作废
	return "", s.db.Where("username = ?", username).Delete(&AuthSession{}).Error
}

// dummyHash 用于账号不存在时也做一次 bcrypt 比较，避免通过响应时间枚举用户名。
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("aig-dummy-password"), bcrypt.DefaultCost)

// Authenticate 校验用户名和密码。
func (s *AuthStore) Authenticate(username, password string) (*AuthAccount, error) {
	var acc AuthAccount
	res := s.db.Where("username = ?", username).Limit(1).Find(&acc)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return nil, ErrInvalidCredentials
	}
	if bcrypt.CompareHashAndPassword([]byte(acc.PasswordHash), []byte(password)) != nil {
		return nil, ErrInvalidCredentials
	}
	return &acc, nil
}

// CreateSession 创建登录会话，返回明文 token（只返回这一次）。
func (s *AuthStore) CreateSession(acc *AuthAccount, ttl time.Duration) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	now := time.Now()
	// 顺手清理已过期会话
	_ = s.db.Where("expires_at < ?", now.UnixMilli()).Delete(&AuthSession{}).Error
	err := s.db.Create(&AuthSession{
		TokenHash: HashToken(token),
		Username:  acc.Username,
		Role:      acc.Role,
		ExpiresAt: now.Add(ttl).UnixMilli(),
		CreatedAt: now.UnixMilli(),
	}).Error
	if err != nil {
		return "", err
	}
	return token, nil
}

// GetSession 根据 token 取会话；不存在或已过期返回 ErrSessionInvalid。
func (s *AuthStore) GetSession(token string) (*AuthSession, error) {
	if token == "" {
		return nil, ErrSessionInvalid
	}
	var sess AuthSession
	res := s.db.Where("token_hash = ?", HashToken(token)).Limit(1).Find(&sess)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, ErrSessionInvalid
	}
	if sess.ExpiresAt <= time.Now().UnixMilli() {
		_ = s.db.Where("token_hash = ?", sess.TokenHash).Delete(&AuthSession{}).Error
		return nil, ErrSessionInvalid
	}
	return &sess, nil
}

// DeleteSession 退出登录。
func (s *AuthStore) DeleteSession(token string) error {
	if token == "" {
		return nil
	}
	return s.db.Where("token_hash = ?", HashToken(token)).Delete(&AuthSession{}).Error
}

// CreateAPIKey 创建 API Key，返回记录和明文（明文只返回这一次）。
func (s *AuthStore) CreateAPIKey(name, createdBy string, expiresAt time.Time) (*APIKey, string, error) {
	now := time.Now()
	if !expiresAt.After(now) {
		return nil, "", fmt.Errorf("expiry must be in the future")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", err
	}
	plain := APIKeyPrefix + base64.RawURLEncoding.EncodeToString(raw)
	key := &APIKey{
		ID:        uuid.NewString(),
		Name:      name,
		KeyHash:   HashToken(plain),
		Prefix:    plain[:len(APIKeyPrefix)+8],
		CreatedBy: createdBy,
		CreatedAt: now.UnixMilli(),
		ExpiresAt: expiresAt.UnixMilli(),
	}
	if err := s.db.Create(key).Error; err != nil {
		return nil, "", err
	}
	return key, plain, nil
}

// ListAPIKeys 按创建时间倒序列出所有 API Key（不含明文）。
func (s *AuthStore) ListAPIKeys() ([]APIKey, error) {
	keys := make([]APIKey, 0)
	err := s.db.Order("created_at DESC").Find(&keys).Error
	return keys, err
}

// RevokeAPIKey 吊销 API Key，立即失效。
func (s *AuthStore) RevokeAPIKey(id string) error {
	res := s.db.Model(&APIKey{}).Where("id = ?", id).Update("revoked", true)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// ValidateAPIKey 校验明文 API Key。
func (s *AuthStore) ValidateAPIKey(plain string) (*APIKey, error) {
	if len(plain) <= len(APIKeyPrefix) || plain[:len(APIKeyPrefix)] != APIKeyPrefix {
		return nil, ErrAPIKeyInvalid
	}
	var key APIKey
	res := s.db.Where("key_hash = ?", HashToken(plain)).Limit(1).Find(&key)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, ErrAPIKeyInvalid
	}
	if key.Revoked {
		return nil, ErrAPIKeyRevoked
	}
	now := time.Now().UnixMilli()
	if key.ExpiresAt <= now {
		return nil, ErrAPIKeyExpired
	}
	if now-key.LastUsedAt > apiKeyLastUsedThrottle.Milliseconds() {
		_ = s.db.Model(&APIKey{}).Where("id = ?", key.ID).Update("last_used_at", now).Error
		key.LastUsedAt = now
	}
	return &key, nil
}
