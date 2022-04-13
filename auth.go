package authr

import (
    "context"
    "errors"
    "fmt"
    "github.com/davecgh/go-spew/spew"
    "github.com/dgrijalva/jwt-go"
    "golang.org/x/crypto/bcrypt"
    "gorm.io/gorm"
    "net/http"
    "os"
    "time"
)

// DbProvider service
type DbProvider func() (*gorm.DB, error)

// AuthService service
type AuthService interface {
    LoadUser(c context.Context, ID string) (*User, error)
    SaveAuth(context.Context, string, *TokenDetails) error
    FetchAuth(context.Context, string) (*AuthTokens, error)
    DeleteRefresh(context.Context, string) error
    DeleteTokens(context.Context, *AccessDetails) error
    RegisterUser(context.Context, *RegistrationParams) (*User, error)
    LoginUser(c context.Context, args *LoginParams) (*User, error)

    // proxied token calls
    CreateToken(u *User) (*TokenDetails, error)
    RefreshToken(u *User, claims jwt.MapClaims) (*TokenDetails, error)
    ExtractTokenMetadata(*http.Request) (*AccessDetails, error)
    RefreshSecret() string
    TokenValid(r *http.Request) error
}

type LoginFailure func(*http.Request, string)
type TokenGranted func(*http.Request, *TokenDetails)
type TokenRevoked func(*http.Request, *TokenDetails)

type AuthReporter struct {
    loginFailure LoginFailure
    tokenGranted TokenGranted
    tokenRevoked TokenRevoked
}

type service struct {
    ts TokenInterface
    db *gorm.DB
    r  *AuthReporter
}

// NewAuthService create new auth service
func NewAuthService(ts TokenInterface, db *gorm.DB, r *AuthReporter) (AuthService, error) {
    s := &service{ts: ts, db: db, r: r}
    err := s.InitialMigration()
    return s, err
}

// SaveAuth metadata to Redis
func (s *service) SaveAuth(c context.Context, userId string, td *TokenDetails) error {

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
func (s *service) FetchAuth(c context.Context, tokenUuid string) (*AuthTokens, error) {

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
func (s *service) FetchHistory(c context.Context, UserId string) ([]AuthTokens, error) {
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
func (s *service) DeleteTokens(c context.Context, authD *AccessDetails) error {
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
func (s *service) DeleteRefresh(c context.Context, refreshUuid string) error {
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

func (s *service) ExtractTokenMetadata(r *http.Request) (*AccessDetails, error) {
    return s.ts.ExtractTokenMetadata(r)
}

func (s *service) CreateToken(u *User) (*TokenDetails, error) {
    return s.ts.CreateToken(u)
}
func (s *service) RefreshToken(u *User, claims jwt.MapClaims) (*TokenDetails, error) {
    return s.ts.RefreshToken(u, claims)
}

func (s *service) RefreshSecret() string {
    return s.ts.RefreshSecret()
}
func (s *service) TokenValid(r *http.Request) error {
    return s.ts.TokenValid(r)
}
