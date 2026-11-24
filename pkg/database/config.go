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
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// Config 用于保存数据库配置
type Config struct {
	// DSN 为 PostgreSQL 连接串，如 postgres://user:pass@host:5432/dbname?sslmode=disable
	DSN string
}

// NewConfig 创建一个新的数据库配置
func NewConfig(dsn string) *Config {
	return &Config{DSN: dsn}
}

// LoadConfigFromEnv 从环境变量 DATABASE_URL 加载数据库配置
func LoadConfigFromEnv() *Config {
	return &Config{DSN: os.Getenv("DATABASE_URL")}
}

// InitDB 用 GORM 连接 PostgreSQL 并返回 *gorm.DB
func InitDB(config *Config) (*gorm.DB, error) {
	if config == nil || config.DSN == "" {
		return nil, errors.New("未配置数据库：请设置环境变量 DATABASE_URL（PostgreSQL 连接串）")
	}

	// 显式关闭参数插值：默认 logger 会把绑定参数展开成明文 SQL，
	// 而 models 表里存有 token 与 extra_headers 这类密钥，
	// 一次失败的 UPDATE 或慢查询就可能把它们写进日志。
	dbLogger := gormlogger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		gormlogger.Config{
			SlowThreshold:        time.Second,
			LogLevel:             gormlogger.Warn,
			ParameterizedQueries: true,
		},
	)
	db, err := gorm.Open(postgres.Open(config.DSN), &gorm.Config{
		Logger: dbLogger,
		// 不在库里建外键约束：应用层按 username 关联，public_user 等并不一定存在于 users 表
		// （与此前的行为保持一致）。
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		return nil, fmt.Errorf("无法连接数据库: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("获取底层数据库连接失败: %w", err)
	}

	// PostgreSQL 默认 max_connections=100（compose 中设为 200），连接数需低于该值
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(50)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)

	return db, nil
}
