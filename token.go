package authr

import (
    "errors"
    "fmt"
    "github.com/dgrijalva/jwt-go"
    "github.com/twinj/uuid"
    "net/http"
    "strings"
    "time"
)

const (
    JwtUserId      = "user_id"
    JwtAccessUuid  = "access_uuid"
    JwtRefreshUuid = "refresh_uuid"
    JwtExpires     = "exp"
    JwtRole        = "role"
)

type tokenService struct {
    accessSecret  string
    refreshSecret string
}

func NewTokenService(accessSecret, refreshSecret string) TokenInterface {
    return &tokenService{accessSecret: accessSecret, refreshSecret: refreshSecret}
}

type TokenInterface interface {
    CreateToken(u *User) (*TokenDetails, error)
    RefreshToken(u *User, claims jwt.MapClaims) (*TokenDetails, error)
    ExtractTokenMetadata(*http.Request) (*AccessDetails, error)
    RefreshSecret() string
    TokenValid(r *http.Request) error
}

//Token implements the TokenInterface
var _ TokenInterface = &tokenService{}

func (t *tokenService) RefreshSecret() string {
    return t.refreshSecret
}

func (t *tokenService) CreateToken(u *User) (*TokenDetails, error) {
    td := &TokenDetails{}
    td.ID = u.ID
    td.Email = u.Email
    td.Username = u.Username
    td.Roles = strings.Split(u.Roles, ",")

    td.AtExpires = time.Now().Add(time.Minute * 30).Unix() //expires after 30 min
    td.TokenUuid = uuid.NewV4().String()

    td.RtExpires = time.Now().Add(time.Hour * 24 * 7).Unix()
    td.RefreshUuid = td.TokenUuid + "++" + u.ID

    var err error
    //Creating Access Token
    atClaims := jwt.MapClaims{}
    atClaims[JwtAccessUuid] = td.TokenUuid
    atClaims[JwtUserId] = u.ID
    atClaims[JwtExpires] = td.AtExpires
    atClaims[JwtRole] = u.Roles

    if u.details != nil {
        for k, v := range u.details {
            atClaims[k] = v
        }
    }

    at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
    td.AccessToken, err = at.SignedString([]byte(t.accessSecret))
    if err != nil {
        return nil, err
    }

    //Creating Refresh Token
    td.RtExpires = time.Now().Add(time.Hour * 24 * 7).Unix()
    td.RefreshUuid = td.TokenUuid + "++" + u.ID

    rtClaims := jwt.MapClaims{}
    rtClaims[JwtRefreshUuid] = td.RefreshUuid
    rtClaims[JwtUserId] = u.ID
    rtClaims[JwtExpires] = td.RtExpires
    rtClaims[JwtRole] = u.Roles
    if u.details != nil {
        for k, v := range u.details {
            rtClaims[k] = v
        }
    }

    rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)

    td.RefreshToken, err = rt.SignedString([]byte(t.refreshSecret))
    if err != nil {
        return nil, err
    }
    return td, nil
}

func (t *tokenService) RefreshToken(u *User, claims jwt.MapClaims) (*TokenDetails, error) {
    td := &TokenDetails{}
    td.ID = u.ID
    td.Email = u.Email
    td.Username = u.Username
    td.Roles = strings.Split(u.Roles, ",")

    td.AtExpires = time.Now().Add(time.Minute * 30).Unix() //expires after 30 min
    td.TokenUuid = uuid.NewV4().String()

    td.RtExpires = time.Now().Add(time.Hour * 24 * 7).Unix()
    td.RefreshUuid = td.TokenUuid + "++" + u.ID

    var err error
    //Creating Access Token
    atClaims := jwt.MapClaims{}
    if claims != nil {
        for k, v := range claims {
            atClaims[k] = v
        }
    }

    atClaims[JwtAccessUuid] = td.TokenUuid
    atClaims[JwtUserId] = u.ID
    atClaims[JwtExpires] = td.AtExpires

    at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
    td.AccessToken, err = at.SignedString([]byte(t.accessSecret))
    if err != nil {
        return nil, err
    }

    //Creating Refresh Token
    td.RtExpires = time.Now().Add(time.Hour * 24 * 7).Unix()
    td.RefreshUuid = td.TokenUuid + "++" + u.ID

    rtClaims := jwt.MapClaims{}
    if claims != nil {
        for k, v := range claims {
            rtClaims[k] = v
        }
    }

    rtClaims[JwtRefreshUuid] = td.RefreshUuid
    rtClaims[JwtUserId] = u.ID
    rtClaims[JwtExpires] = td.RtExpires

    rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)

    td.RefreshToken, err = rt.SignedString([]byte(t.refreshSecret))
    if err != nil {
        return nil, err
    }
    return td, nil

}

func (t *tokenService) TokenValid(r *http.Request) error {
    token, err := t.verifyToken(r)
    if err != nil {
        return err
    }
    if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
        return err
    }
    return nil
}

func (t *tokenService) verifyToken(r *http.Request) (*jwt.Token, error) {
    tokenString := t.extractToken(r)
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return []byte(t.accessSecret), nil
    })
    if err != nil {
        return nil, err
    }
    return token, nil
}

//get the token from the request body
func (t *tokenService) extractToken(r *http.Request) string {
    bearToken := r.Header.Get("Authorization")
    strArr := strings.Split(bearToken, " ")
    if len(strArr) == 2 {
        return strArr[1]
    }
    return ""
}

func (t *tokenService) extract(token *jwt.Token) (*AccessDetails, error) {

    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok || !token.Valid {
        return nil, errors.New("something went wrong")
    }
    accessUuid, ok := claims[JwtAccessUuid].(string)
    if !ok {
        return nil, errors.New("something went wrong")
    }

    userId, ok := claims[JwtUserId].(string)
    if !ok {
        return nil, errors.New("unauthorized")
    }

    role, ok := claims[JwtRole].(string)
    if !ok {
        return nil, errors.New("unauthorized")
    }

    return &AccessDetails{
        TokenUuid: accessUuid,
        UserId:    userId,
        Role:      role,
        Claims:    claims,
    }, nil

}

func (t *tokenService) ExtractTokenMetadata(r *http.Request) (*AccessDetails, error) {
    token, err := t.verifyToken(r)
    if err != nil {
        return nil, err
    }
    acc, err := t.extract(token)
    if err != nil {
        return nil, err
    }
    return acc, nil
}
