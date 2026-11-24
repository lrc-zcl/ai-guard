// Copyright (c) 2024-2026 Tencent Zhuque Lab. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Requirement: Any integration or derivative work must explicitly attribute
// Tencent Zhuque Lab (https://github.com/Tencent/AI-Infra-Guard) in its
// documentation or user interface, as detailed in the NOTICE file.

package database

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/gorm"
)

var testSchemaSeq atomic.Int64

// NewTestDB 返回一个连到 PostgreSQL 的独立测试库（每个测试一个独立 schema，结束后自动删除）。
// 需要设置环境变量 TEST_DATABASE_URL（URL 形式的 PostgreSQL 连接串），未设置则跳过该测试。
// 例如：TEST_DATABASE_URL=postgres://aig:aig_password@localhost:5432/aig?sslmode=disable
func NewTestDB(t testing.TB) *gorm.DB {
	t.Helper()
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("未设置 TEST_DATABASE_URL，跳过需要 PostgreSQL 的测试")
	}

	admin, err := InitDB(NewConfig(base))
	if err != nil {
		t.Fatalf("连接测试数据库失败: %v", err)
	}

	schema := fmt.Sprintf("t_%d_%d", time.Now().UnixNano(), testSchemaSeq.Add(1))
	if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		t.Fatalf("创建测试 schema 失败: %v", err)
	}

	u, err := url.Parse(base)
	if err != nil || !strings.HasPrefix(u.Scheme, "postgres") {
		t.Fatalf("TEST_DATABASE_URL 必须是 postgres:// 形式的 URL: %v", err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()

	db, err := InitDB(NewConfig(u.String()))
	if err != nil {
		t.Fatalf("连接测试 schema 失败: %v", err)
	}

	t.Cleanup(func() {
		if sqlDB, _ := db.DB(); sqlDB != nil {
			_ = sqlDB.Close()
		}
		_ = admin.Exec("DROP SCHEMA " + schema + " CASCADE").Error
		if sqlDB, _ := admin.DB(); sqlDB != nil {
			_ = sqlDB.Close()
		}
	})
	return db
}
