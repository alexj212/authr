package main

import (
    "authr"
    "context"
    "fmt"
    "github.com/gin-contrib/cors"
    "github.com/gin-gonic/gin"
    "gorm.io/driver/sqlite"
    "gorm.io/gorm/logger"

    _ "gorm.io/driver/sqlite"
    "gorm.io/gorm"

    "github.com/joho/godotenv"
    "log"
    "net/http"
    "os"
    "os/signal"
    "time"
)

func init() {
    if err := godotenv.Load(); err != nil {
        log.Print("No .env file found")
    }
}

func main() {

    appAddr := ":" + os.Getenv("PORT")
    accessSecret := os.Getenv("ACCESS_SECRET")
    refreshSecret := os.Getenv("REFRESH_SECRET")

    db, err := GetDatabase()
    if err != nil {
        log.Fatal("GetDatabase error:", err)
    }

    var ts = authr.NewTokenService(accessSecret, refreshSecret)
    var as = authr.NewAuthService(ts, db)

    var service = NewProfile(as, ts)

    var router = gin.Default()
    // CORS for https://foo.com and https://github.com origins, allowing:
    // - PUT and PATCH methods
    // - Origin header
    // - Credentials share
    // - Preflight requests cached for 12 hours
    router.Use(cors.New(cors.Config{
        AllowOrigins:     []string{"*"},
        AllowMethods:     []string{"*"},
        AllowHeaders:     []string{"*"},
        ExposeHeaders:    []string{"Content-Length"},
        AllowCredentials: true,
        AllowOriginFunc: func(origin string) bool {
            return true
        },
        MaxAge: 12 * time.Hour,
    }))

    router.POST("/login", as.Login)
    router.POST("/refresh", as.Refresh)
    router.POST("/register", as.Register)
    router.POST("/logout", as.Logout)
    router.GET("/whoami", as.Whoami)
    router.GET("/sessions", as.Sessions)

    router.POST("/todo", authr.TokenAuthMiddleware(ts), service.CreateTodo)
    router.GET("/todo", authr.TokenAuthMiddleware(ts), service.CreateTodo)

    //router.POST("/api", service.Api)
    router.GET("/api/test/all", service.PublicContent)
    router.GET("/api/test/user", authr.TokenAuthMiddleware(ts), service.UserBoard)
    router.GET("/api/test/mod", authr.TokenAuthMiddleware(ts), service.ModeratorBoard)
    router.GET("/api/test/admin", authr.TokenAuthMiddleware(ts), service.AdminBoard)

    srv := &http.Server{
        Addr:    appAddr,
        Handler: router,
    }
    go func() {
        if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            log.Fatalf("listen: %s\n", err)
        }
    }()
    //Wait for interrupt signal to gracefully shut down the server with a timeout of 10 seconds
    quit := make(chan os.Signal)
    signal.Notify(quit, os.Interrupt)
    <-quit
    log.Println("Shutdown Server ...")

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    if err := srv.Shutdown(ctx); err != nil {
        log.Fatal("Server Shutdown:", err)
    }
    log.Println("Server exiting")
}

// GetDatabase returns database connection
func GetDatabase() (*gorm.DB, error) {
    newLogger := logger.New(
        log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
        logger.Config{
            SlowThreshold: time.Second, // Slow SQL threshold
            // LogLevel:                  logger.Info, // Log level
            IgnoreRecordNotFoundError: false, // Ignore ErrRecordNotFound error for logger
            Colorful:                  true,  // Disable color
        },
    )

    gormConf := &gorm.Config{
        Logger: newLogger,
    }

    connection, err := gorm.Open(sqlite.Open("test.db"), gormConf)
    if err != nil {
        log.Fatalln("Invalid database url")
    }

    sqldb, err := connection.DB()
    if err != nil {
        return nil, err
    }

    err = sqldb.Ping()
    if err != nil {
        return nil, err
    }
    fmt.Println("Database connection successful.")
    return connection, nil
}
