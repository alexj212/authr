package main

import (
    "context"
    "fmt"
    "github.com/alexj212/authr"

    "github.com/gorilla/mux"
    "github.com/rs/cors"
    "gorm.io/driver/sqlite"
    _ "gorm.io/driver/sqlite"
    "gorm.io/gorm"
    "gorm.io/gorm/logger"
    "log"
    "net/http"

    "github.com/joho/godotenv"
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

    report := &authr.AuthReporter{}
    as, err := authr.NewAuthService(ts, db, report)
    g := authr.NewHttpAdapter(as)

    var service = NewProfile(as, ts)

    router := mux.NewRouter()
    // CORS for https://foo.com and https://github.com origins, allowing:
    // - PUT and PATCH methods
    // - Origin header
    // - Credentials share
    // - Preflight requests cached for 12 hours
    c := cors.New(cors.Options{
        AllowedOrigins:   []string{"*"},
        AllowedMethods:   []string{"*"},
        AllowedHeaders:   []string{"*"},
        ExposedHeaders:   []string{"Content-Length"},
        AllowCredentials: true,
        AllowOriginFunc: func(origin string) bool {
            return true
        },
        // MaxAge: 12 * time.Hour,
    })

    router.HandleFunc("/login", g.Login).Methods("POST")
    router.HandleFunc("/refresh", g.Refresh).Methods("POST")
    router.HandleFunc("/register", g.Register).Methods("POST")
    router.HandleFunc("/logout", g.Logout).Methods("POST")
    router.HandleFunc("/whoami", g.Whoami).Methods("GET")
    router.HandleFunc("/sessions", g.Sessions).Methods("GET")

    router.Handle("/todo", g.TokenAuthMiddleware(http.HandlerFunc(service.CreateTodo))).Methods("POST")
    router.Handle("/todo", g.TokenAuthMiddleware(http.HandlerFunc(service.CreateTodo))).Methods("GET")

    //router.POST("/api", service.Api)
    router.Handle("/api/test/all", http.HandlerFunc(service.PublicContent)).Methods("GET")
    router.Handle("/api/test/user", g.TokenAuthMiddleware(http.HandlerFunc(service.UserBoard))).Methods("GET")
    router.Handle("/api/test/mod", g.TokenAuthMiddleware(http.HandlerFunc(service.ModeratorBoard))).Methods("GET")
    router.Handle("/api/test/admin", g.TokenAuthMiddleware(http.HandlerFunc(service.AdminBoard))).Methods("GET")

    handler := c.Handler(router)

    srv := &http.Server{
        Addr:    appAddr,
        Handler: handler,
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
