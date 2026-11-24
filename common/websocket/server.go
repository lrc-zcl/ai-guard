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

// @title AI-Infra-Guard 任务API
// @version 1.0
// @description API for managing AI security scanning tasks
// @BasePath /
package websocket

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"fmt"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/Tencent/AI-Infra-Guard/common/apichecker"
	"github.com/Tencent/AI-Infra-Guard/common/trpc"
	_ "github.com/Tencent/AI-Infra-Guard/docs"
	version "github.com/Tencent/AI-Infra-Guard/internal/options"
	"github.com/Tencent/AI-Infra-Guard/pkg/database"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"gorm.io/gorm"
	"trpc.group/trpc-go/trpc-go/log"
)

//go:embed static/*
var staticFS embed.FS

// adminUsername 内置管理员账号名。
const adminUsername = "admin"

func RunWebServer(options *version.Options) {
	// 1. 初始化trpc-go
	if err := trpc.InitTrpc("./trpc_go.yaml"); err != nil {
		log.Fatalf("Trpc-go初始化失败: %v", err)
	}
	log.Infof("Trpc-go initialized successfully: trace_id=system_startup")

	r := gin.Default()
	// 2. 添加中间件
	//r.Use(middleware.TrpcMiddleware())
	//r.Use(middleware.RequestLoggerMiddleware()) // 添加请求参数日志中间件
	// r.Use(middleware.MetricsMiddleware()) // 移除HTTP监控中间件，依赖TRPC自动监控

	// 3. 初始化数据库和Agentmanager
	dbConfig := database.LoadConfigFromEnv() // 从环境变量加载数据库配置
	db, err := database.InitDB(dbConfig)
	if err != nil {
		log.Errorf("数据库初始化失败: trace_id=system_startup, error=%v", err)

	}
	taskStore := database.NewTaskStore(db)
	if err := taskStore.Init(); err != nil {
		log.Errorf("初始化tasks表失败: trace_id=system_startup, error=%v", err)
		log.Fatalf("初始化tasks表失败: %v", err)
	}

	// 初始化模型存储
	modelStore := database.NewModelStore(db)
	if err := modelStore.Init(); err != nil {
		log.Errorf("初始化models表失败: trace_id=system_startup, error=%v", err)

	}
	// 自动添加模型
	modelStore.AutoAddModels()

	// 初始化认证：管理员账号、登录会话、API Key
	auth := initAuthenticator(db)

	if options.APICheckerURL != "" {
		apiCheckerProxy, proxyErr := apichecker.NewWithModelStore(options.APICheckerURL, modelStore)
		if proxyErr != nil {
			log.Errorf("API Checker 代理配置无效: trace_id=system_startup, error=%v", proxyErr)
		} else {
			apiCheckerProxy.EnableConfiguredModelResolution(setupIdentityMiddleware())
			// API Checker 代理同样需要登录态或 API Key
			apiCheckerProxy.Register(r.Group("", auth.Authenticate()))
			log.Infof(
				"API Checker proxy initialized: trace_id=system_startup, upstream=%s",
				options.APICheckerURL,
			)
		}
	}

	// 初始化AgentManager
	agentManager := NewAgentManager()

	// 初始化ModelManager
	modelManager := NewModelManager(modelStore)

	// 初始化文件上传配置（支持环境变量）
	fileConfig := LoadFileUploadConfigFromEnv()

	// 验证文件上传配置
	if err := fileConfig.ValidateConfig(); err != nil {
		log.Errorf("文件上传配置验证失败: trace_id=system_startup, error=%v", err)

	}

	// 初始化SSE管理器
	sseManager := NewSSEManager()

	taskManager := NewTaskManager(agentManager, taskStore, modelStore, fileConfig, sseManager)
	err = taskManager.taskStore.ResetRunningTasks()
	if err != nil {
		log.Fatalf("重置运行中的任务失败: %v", err)
	}

	// 将 TaskManager 注入到 AgentManager
	agentManager.SetTaskManager(taskManager)

	// API 版本分组
	v1 := r.Group("/api/v1")
	// 登录/退出必须在 Use(鉴权) 之前注册：gin 的 Use 只对其后注册的路由生效，
	// 所以这两个是公开的，其余 /api/v1 下的接口都要求登录态或 API Key。
	v1.POST("/auth/login", auth.HandleLogin)
	v1.POST("/auth/logout", auth.HandleLogout)
	v1.Use(auth.Authenticate())
	{
		// 当前登录信息（前端据此判断是否已登录、是否为 admin）
		v1.GET("/auth/me", auth.HandleMe)
		// API Key 管理：只有 admin 通过网页登录才能操作
		apiKeys := v1.Group("/auth/api-keys", auth.RequireAdminSession())
		{
			apiKeys.GET("", auth.HandleListAPIKeys)
			apiKeys.POST("", auth.HandleCreateAPIKey)
			apiKeys.DELETE("/:id", auth.HandleRevokeAPIKey)
		}

		v1.GET("/images/:path", func(context *gin.Context) {
			path := context.Param("path")
			if strings.Contains(path, "..") {
				context.String(403, "Forbidden")
				return
			}
			context.File(filepath.Join("uploads", path))
		})
		// 1. 知识库模块
		knowledge := v1.Group("/knowledge")
		knowledge.Use(setupIdentityMiddleware())
		{
			// AI应用指纹
			fingerprints := knowledge.Group("/fingerprints")
			{
				// 管理功能
				fingerprints.GET("", HandleListFingerprints)
				fingerprints.POST("", HandleCreateFingerprint)
				fingerprints.PUT("/:name", HandleEditFingerprint)
				fingerprints.DELETE("", HandleDeleteFingerprint)
			}
			// 漏洞库
			vulnerabilities := knowledge.Group("/vulnerabilities")
			{
				// 管理功能
				vulnerabilities.GET("", HandleListVulnerabilities())
				vulnerabilities.POST("", HandleCreateVulnerability())
				vulnerabilities.PUT("/:cve", HandleEditVulnerability)
				vulnerabilities.DELETE("", HandleBatchDeleteVulnerabilities)
			}
			// 评测集
			evaluations := knowledge.Group("/evaluations")
			{
				// 管理功能
				evaluations.GET("/:name", HandleGetEvaluationDetail)
				evaluations.GET("", HandleListEvaluations)
				evaluations.POST("", HandleCreateEvaluation)
				evaluations.PUT("/:name", HandleEditEvaluation)
				evaluations.DELETE("", HandleDeleteEvaluation)
			}
			// MCP
			mcp := knowledge.Group("/mcp")
			{
				mcp.GET("names", GetMcpPluginList)
				mcp.GET("", HandleList(MCPROOT, McpLoadFile))
				mcp.POST("", HandleCreate(mcpReadAndSave))
				mcp.PUT("/:id", HandleEdit(mcpUpdateFunc))
				mcp.DELETE("/:id", HandleDelete(mcpDeleteFunc))
			}
			// Prompt Collections
			collections := knowledge.Group("/prompt_collections")
			{
				collections.GET("", HandleList(PromptCollectionsRoot, promptCollectionLoadFile))
				collections.POST("", HandleCreate(promptCollectionReadAndSave))
				collections.PUT("/:id", HandleEdit(promptCollectionUpdateFunc))
				collections.DELETE("", HandleDelete(promptCollectionDeleteFunc))
			}
			agentConfigs := knowledge.Group("/agent")
			{
				agentConfigs.GET("/names", HandleListAgentNames)
				agentConfigs.GET("/:name", HandleGetAgentConfig)
				agentConfigs.POST("/:name", HandleSaveAgentConfig)
				agentConfigs.DELETE("/:name", HandleDeleteAgentConfig)
				agentConfigs.POST("/connect", HandleAgentConnect)
				agentConfigs.POST("/prompt_test", HandleAgentPromptTest)
				agentConfigs.GET("/template", HandleAgentTemplate)
			}
			// 算子列表
			knowledge.GET("/jailbreak", GetJailBreak)
		}
		appSecurity := v1.Group("/app")
		{
			appSecurity.Use(setupIdentityMiddleware())
			// 任务管理
			tasks := appSecurity.Group("/tasks")
			{
				// 获取任务列表接口
				tasks.GET("", func(c *gin.Context) {
					HandleGetTaskList(c, taskManager)
				})
				// 获取任务详情接口
				tasks.GET("/:sessionId", func(c *gin.Context) {
					HandleGetTaskDetail(c, taskManager)
				})
				// 分享任务接口
				tasks.POST("/share", func(c *gin.Context) {
					HandleShare(c, taskManager)
				})
				// SSE接口
				tasks.GET("/sse/:sessionId", func(c *gin.Context) {
					HandleTaskSSE(c, taskManager)
				})
				// 新建任务接口
				tasks.POST("", func(c *gin.Context) {
					HandleTaskCreate(c, taskManager)
				})
				// 文件上传接口（完整文件上传）
				tasks.POST("/uploadFile", func(c *gin.Context) {
					HandleUploadFile(c, taskManager)
				})
				// 分片上传接口
				tasks.POST("/uploadChunk", func(c *gin.Context) {
					HandleUploadFileChunk(c, taskManager)
				})
				// 合并分片接口
				tasks.POST("/mergeChunks", func(c *gin.Context) {
					HandleMergeFileChunks(c, taskManager)
				})
				// 文件下载接口
				tasks.POST("/:sessionId/downloadFile", func(c *gin.Context) {
					HandleDownloadFile(c, taskManager)
				})
				// 编辑任务接口
				tasks.PUT("/:sessionId", func(c *gin.Context) {
					HandleUpdateTask(c, taskManager)
				})
				// 删除任务接口
				tasks.DELETE("/:sessionId", func(c *gin.Context) {
					HandleDeleteTask(c, taskManager)
				})
				// 终止任务接口
				tasks.POST("/:sessionId/terminate", func(c *gin.Context) {
					HandleTerminateTask(c, taskManager)
				})
			}
			// 模型管理
			models := appSecurity.Group("/models")
			{
				// 获取模型列表接口
				models.GET("", func(c *gin.Context) {
					HandleGetModelList(c, modelManager)
				})
				// 获取模型详情接口
				models.GET("/:modelId", func(c *gin.Context) {
					HandleGetModelDetail(c, modelManager)
				})
				// 创建模型接口
				models.POST("", func(c *gin.Context) {
					HandleCreateModel(c, modelManager)
				})
				// 更新模型接口
				models.PUT("/:modelId", func(c *gin.Context) {
					HandleUpdateModel(c, modelManager)
				})
				// 删除模型接口（支持单个和批量）
				models.DELETE("", func(c *gin.Context) {
					HandleDeleteModel(c, modelManager)
				})
			}
		}
		// 4. Agent 管理
		agents := v1.Group("/agents")
		{
			// 只需要WebSocket入口
			agents.GET("/ws", agentManager.HandleAgentWebSocket())
		}
		// 提供给第三方的api
		taskApi := appSecurity.Group("/taskapi")
		{
			// 创建任务
			taskApi.POST("/tasks", func(c *gin.Context) {
				SubmitTask(c, taskManager)
			})
			// 获取任务状态
			taskApi.GET("/status/:id", func(c *gin.Context) {
				GetTaskStatus(c, taskManager)
			})
			// 获取任务结果
			taskApi.GET("/result/:id", func(c *gin.Context) {
				GetTaskResult(c, taskManager)
			})
			taskApi.POST("/upload", func(c *gin.Context) {
				HandleUploadFile(c, taskManager)
			})
			// 分片上传接口
			taskApi.POST("/uploadChunk", func(c *gin.Context) {
				HandleUploadFileChunk(c, taskManager)
			})
			// 合并分片接口
			taskApi.POST("/mergeChunks", func(c *gin.Context) {
				HandleMergeFileChunks(c, taskManager)
			})
		}
		// version
		v1.GET("/version", func(c *gin.Context) {
			filename := "CHANGELOG.md"
			data, err := os.ReadFile(filename)
			if err != nil {
				data = []byte("")
			}
			c.JSON(http.StatusOK, gin.H{
				"version":   version.GetVersion(),
				"changelog": string(data),
			})
		})

		// system — data directory auto-sync & version check
		system := v1.Group("/system")
		system.Use(setupIdentityMiddleware())
		{
			system.POST("/update-data", HandleTriggerDataUpdate)
			system.GET("/update-data", HandleGetUpdateStatus)
			system.GET("/version", HandleVersionCheck)
		}
	}

	// Swagger UI - 必须在 NoRoute 之前注册
	r.GET("/docs/*any", func(c *gin.Context) {
		if c.Request.URL.Path == "/docs/" {
			c.Redirect(302, "/docs/index.html")
		} else {
			ginSwagger.WrapHandler(swaggerFiles.Handler)(c)
		}
	})

	// 静态文件处理
	r.NoRoute(serveStaticFallback)

	log.Infof("Starting WebServer: trace_id=system_startup, addr=%s", options.WebServerAddr)
	if err := r.Run(options.WebServerAddr); err != nil {
		log.Errorf("Could not start WebSocket server: trace_id=system_startup, error=%s", err)
	}
}

func serveStaticFallback(c *gin.Context) {
	path := c.Request.URL.Path
	if strings.HasPrefix(path, "/api/") ||
		path == apichecker.ServicePrefix ||
		strings.HasPrefix(path, apichecker.ServicePrefix+"/") {
		c.JSON(http.StatusNotFound, gin.H{"detail": "API endpoint not found"})
		return
	}

	assetPath := "static" + path
	if path == "/" {
		assetPath = "static/index.html"
	}

	assetData, err := staticFS.ReadFile(assetPath)
	if err != nil {
		assetData, err = staticFS.ReadFile("static/index.html")
		if err != nil {
			c.String(http.StatusInternalServerError, "Internal Server Error")
			return
		}
		c.Header("Content-Type", "text/html")
		c.Data(http.StatusOK, "text/html", assetData)
		return
	}

	mimeType := mime.TypeByExtension(filepath.Ext(assetPath))
	if mimeType == "" {
		mimeType = "text/plain"
	}
	c.Header("Content-Type", mimeType)
	c.Data(http.StatusOK, mimeType, assetData)
}

// initAuthenticator 初始化认证模块。
//
//   - AIG_ADMIN_PASSWORD：admin 密码。设置后每次启动都以它为准；未设置且 admin 不存在时
//     生成随机密码并打印一次。
//   - AIG_AGENT_TOKEN：Agent 连接 Server 的内部凭据，Server 与所有 Agent 必须一致。
//     未设置时生成随机值，此时独立部署的 Agent 无法连接，启动日志会给出提示。
func initAuthenticator(db *gorm.DB) *Authenticator {
	authStore := database.NewAuthStore(db)
	if err := authStore.Init(); err != nil {
		log.Fatalf("初始化认证表失败: %v", err)
	}

	generated, err := authStore.EnsureAdmin(adminUsername, os.Getenv("AIG_ADMIN_PASSWORD"))
	if err != nil {
		log.Fatalf("初始化 admin 账号失败: %v", err)
	}
	if generated != "" {
		fmt.Fprintf(os.Stderr, "\n==============================================================\n"+
			" 已创建管理员账号（该密码只显示这一次，请立即保存）\n"+
			"   用户名: %s\n"+
			"   密  码: %s\n"+
			" 如需固定密码，请设置环境变量 AIG_ADMIN_PASSWORD 后重启\n"+
			"==============================================================\n\n", adminUsername, generated)
	}

	agentToken := os.Getenv("AIG_AGENT_TOKEN")
	if agentToken == "" {
		raw := make([]byte, 24)
		if _, err := rand.Read(raw); err != nil {
			log.Fatalf("生成 Agent 凭据失败: %v", err)
		}
		agentToken = hex.EncodeToString(raw)
		fmt.Fprintln(os.Stderr, "[警告] 未设置 AIG_AGENT_TOKEN：已生成临时凭据，独立部署的 Agent 将无法连接。"+
			"请在 Server 和所有 Agent 上设置相同的 AIG_AGENT_TOKEN。")
	}
	return NewAuthenticator(authStore, agentToken)
}

// 配置身份认证中间件
func setupIdentityMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 优先从请求头获取username字段
		username := c.GetHeader("username")

		// 如果都没有，使用默认的公共用户
		if username == "" {
			username = "public_user"
		}
		// 存储到gin上下文
		c.Set("username", username)
		c.Next()
	}
}
