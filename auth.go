package authr

import (
    "context"
    "errors"
    "fmt"
    "github.com/davecgh/go-spew/spew"
    "github.com/gin-gonic/gin"
    "golang.org/x/crypto/bcrypt"
    "gorm.io/gorm"
    "os"
    "time"
)

// DbProvider service
type DbProvider func() (*gorm.DB, error)

// AuthService service
type AuthService interface {
    SaveAuth(context.Context, string, *TokenDetails) error
    FetchAuth(context.Context, string) (*AuthTokens, error)
    DeleteRefresh(context.Context, string) error
    DeleteTokens(context.Context, *AccessDetails) error
    RegisterUser(context.Context, *RegistrationParams) (*User, error)
    LoginUser(c context.Context, args *LoginParams) (*User, error)

    Login(c *gin.Context)
    Register(c *gin.Context)
    Logout(c *gin.Context)
    Refresh(c *gin.Context)
    Whoami(c *gin.Context)
    Sessions(c *gin.Context)
}

type service struct {
    ts TokenInterface
    db *gorm.DB
}

func NewAuthService(ts TokenInterface, db *gorm.DB) AuthService {
    svc := &service{ts: ts, db: db}
    svc.InitialMigration()
    return svc
}

// SaveAuth metadata to Redis
func (s *service) SaveAuth(ctx context.Context, userId string, td *TokenDetails) error {

    at := AuthTokens{
        Expires:   time.Unix(td.AtExpires, 0),
        TokenUuid: td.TokenUuid,
        TokenType: 0,
        UserId:    userId,
    }
    rt := AuthTokens{
        Expires:   time.Unix(td.RtExpires, 0),
        TokenUuid: td.RefreshUuid,
        TokenType: 1,
        UserId:    userId,
    }

    err := s.db.Create(&at).Error
    if err != nil {
        fmt.Printf("SaveAuth at error: %v\n", err)
        os.Exit(1)
        return err
    }

    err = s.db.Create(&rt).Error
    if err != nil {
        fmt.Printf("SaveAuth rt error: %v\n", err)
        os.Exit(2)
        return err
    }

    fmt.Printf("SaveAuth saved\n")
    return nil
}

// FetchAuth Check the metadata saved
func (s *service) FetchAuth(ctx context.Context, tokenUuid string) (*AuthTokens, error) {

    info := &AuthTokens{}

    if err := s.db.Where("token_uuid = ?", tokenUuid).First(info).Error; err != nil {
        fmt.Printf("FetchAuth at error: %v\n", err)
        return nil, err
    }

    now := time.Now()
    if now.After(info.Expires) {
        fmt.Printf("FetchAuth token is expired\n")
        return nil, errors.New("token is expired")
    }

    spew.Dump(info)
    fmt.Printf("FetchAuth valid\n")
    return info, nil
}

// FetchHistory fetch history
func (s *service) FetchHistory(ctx context.Context, UserId string) ([]AuthTokens, error) {
    var tokens []AuthTokens

    if err := s.db.Where("user_id = ?", UserId).Find(tokens).Error; err != nil {
        fmt.Printf("FetchHistory error: %v\n", err)
        return nil, err
    }

    spew.Dump(tokens)
    fmt.Printf("FetchHistory valid\n")
    return tokens, nil
}

// DeleteTokens Once a user row in the token table
func (s *service) DeleteTokens(ctx context.Context, authD *AccessDetails) error {
    //get the refresh uuid
    refreshUuid := fmt.Sprintf("%s++%s", authD.TokenUuid, authD.UserId)
    //delete access token
    err := s.db.Where("token_uuid = ?", authD.TokenUuid).Delete(&AuthTokens{}).Error
    if err != nil {
        fmt.Printf("DeleteTokens TokenUuid error: %v\n", err)
        return err
    }
    //delete refresh token
    err = s.db.Where("token_uuid = ?", refreshUuid).Delete(&AuthTokens{}).Error
    if err != nil {
        fmt.Printf("DeleteTokens refreshUuid error: %v\n", err)
        return err
    }
    fmt.Printf("DeleteTokens valid\n")
    return nil
}

// DeleteRefresh remove refresh token
func (s *service) DeleteRefresh(ctx context.Context, refreshUuid string) error {
    //delete refresh token
    err := s.db.Where("token_uuid = ?", refreshUuid).Delete(&AuthTokens{}).Error
    if err != nil {
        fmt.Printf("DeleteRefresh refreshUuid error: %v\n", err)
        return err
    }

    fmt.Printf("DeleteRefresh valid\n")
    return nil
}

// GeneratePasswordHash take password as input and generate new hash password from it
func GeneratePasswordHash(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
    return string(bytes), err
}

// CheckPasswordHash compare plain password with hash password
func CheckPasswordHash(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}
