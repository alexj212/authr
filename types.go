package authr

import (
    "fmt"
    "github.com/dgrijalva/jwt-go"
    "gorm.io/gorm"
    "time"
)

type LoginParams struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

type RegistrationParams struct {
    Username string `json:"username"`
    Password string `json:"password"`
    Email    string `json:"email"`
}

type User struct {
    gorm.Model
    ID       string                 `json:"id"`
    Username string                 `gorm:"unique" json:"username"`
    Email    string                 `json:"email"`
    Password string                 `json:"password"`
    Roles    string                 `json:"roles"`
    details  map[string]interface{} `json:"-"`
}

type AuthTokens struct {
    gorm.Model
    Expires   time.Time
    TokenUuid string `gorm:"unique"`
    TokenType uint
    UserId    string
}

type AccessDetails struct {
    TokenUuid string
    UserId    string
    Role      string
    Claims    jwt.MapClaims
}

type TokenDetails struct {
    ID           string   `json:"id"`
    Username     string   `json:"username"`
    Email        string   `json:"email"`
    Roles        []string `json:"roles"`
    AccessToken  string   `json:"access_token"`
    RefreshToken string   `json:"refresh_token"`
    TokenUuid    string   `json:"-"`
    RefreshUuid  string   `json:"-"`
    AtExpires    int64    `json:"-"`
    RtExpires    int64    `json:"-"`
}

type Role int64

const (
    RoleAdmin Role = iota
    RoleModerator
)

func (s Role) String() string {
    switch s {
    case RoleAdmin:
        return "ROLE_ADMIN"
    case RoleModerator:
        return "ROLE_MODERATOR"
    default:
        return fmt.Sprintf("ROLE:%d", s)
    }
}
