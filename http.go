package authr

import (
    "encoding/json"
    "fmt"
    "github.com/dgrijalva/jwt-go"
    "net/http"
)

// HttpAdapter mux func exposed
type HttpAdapter interface {
    Login(w http.ResponseWriter, r *http.Request)
    Register(w http.ResponseWriter, r *http.Request)
    Logout(w http.ResponseWriter, r *http.Request)
    Refresh(w http.ResponseWriter, r *http.Request)
    Whoami(w http.ResponseWriter, r *http.Request)
    Sessions(w http.ResponseWriter, r *http.Request)
    TokenAuthMiddleware(next http.Handler) http.Handler
}

func NewHttpAdapter(s AuthService) HttpAdapter {
    g := &httpAdapter{s: s}
    return g
}

type httpAdapter struct {
    s AuthService
}

func (g *httpAdapter) TokenAuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

        err := g.s.TokenValid(r)
        if err != nil {
            JSON(w, http.StatusUnauthorized, "unauthorized")
            return
        }

        next.ServeHTTP(w, r)
    })
}

func (g *httpAdapter) Login(w http.ResponseWriter, r *http.Request) {

    metadata, _ := g.s.ExtractTokenMetadata(r)
    if metadata != nil {
        deleteErr := g.s.DeleteTokens(r.Context(), metadata)
        if deleteErr != nil {
            JSON(w, http.StatusBadRequest, deleteErr.Error())
            return
        }
    }

    var loginArgs LoginParams
    if err := ShouldBindJSON(r, &loginArgs); err != nil {
        JSON(w, http.StatusUnprocessableEntity, "Invalid json provided")
        return
    }

    user, err := g.s.LoginUser(r.Context(), &loginArgs)
    if err != nil {
        JSON(w, http.StatusUnprocessableEntity, err.Error())
        return
    }

    //compare the user from the request, with the one we defined:
    if user == nil {
        JSON(w, http.StatusUnauthorized, "Please provide valid login details")
        return
    }
    ts, err := g.s.CreateToken(user)
    if err != nil {
        JSON(w, http.StatusUnprocessableEntity, err.Error())
        return
    }
    saveErr := g.s.SaveAuth(r.Context(), user.ID, ts)
    if saveErr != nil {
        JSON(w, http.StatusUnprocessableEntity, saveErr.Error())
        return
    }

    JSON(w, http.StatusOK, ts)
}

func (g *httpAdapter) Register(w http.ResponseWriter, r *http.Request) {

    metadata, _ := g.s.ExtractTokenMetadata(r)
    if metadata != nil {
        JSON(w, http.StatusUnauthorized, "unable to register - user is logged in")
        return
    }

    var regArgs RegistrationParams
    if err := ShouldBindJSON(r, &regArgs); err != nil {
        JSON(w, http.StatusUnprocessableEntity, "Invalid json provided")
        return
    }

    user, err := g.s.RegisterUser(r.Context(), &regArgs)
    if err != nil {
        JSON(w, http.StatusUnprocessableEntity, "error occurred")
        return
    }

    if user == nil {
        JSON(w, http.StatusUnauthorized, "Please provide valid registration details")
        return
    }

    ts, err := g.s.CreateToken(user)
    if err != nil {
        JSON(w, http.StatusUnprocessableEntity, err.Error())
        return
    }
    saveErr := g.s.SaveAuth(r.Context(), user.ID, ts)
    if saveErr != nil {
        JSON(w, http.StatusUnprocessableEntity, saveErr.Error())
        return
    }

    JSON(w, http.StatusOK, ts)
}

func (g *httpAdapter) Logout(w http.ResponseWriter, r *http.Request) {
    //If metadata is passed and the tokens valid, delete them from the redis store
    metadata, _ := g.s.ExtractTokenMetadata(r)
    if metadata != nil {
        deleteErr := g.s.DeleteTokens(r.Context(), metadata)
        if deleteErr != nil {
            JSON(w, http.StatusBadRequest, deleteErr.Error())
            return
        }
    }
    JSON(w, http.StatusOK, "Successfully logged out")
}

func (g *httpAdapter) Refresh(w http.ResponseWriter, r *http.Request) {
    mapToken := map[string]string{}
    if err := ShouldBindJSON(r, &mapToken); err != nil {
        JSON(w, http.StatusUnprocessableEntity, err.Error())
        return
    }
    refreshToken := mapToken["refresh_token"]

    //verify the token
    token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return []byte(g.s.RefreshSecret()), nil
    })
    //if there is an error, the token must have expired
    if err != nil {
        JSON(w, http.StatusUnauthorized, "Refresh token expired")
        return
    }
    //is token valid?
    if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
        JSON(w, http.StatusUnauthorized, err)
        return
    }
    //Since token is valid, get the uuid:
    claims, ok := token.Claims.(jwt.MapClaims) //the token claims should conform to MapClaims
    if ok && token.Valid {
        refreshUuid, ok := claims[JwtRefreshUuid].(string) //convert the interface to string
        if !ok {
            JSON(w, http.StatusUnprocessableEntity, err)
            return
        }
        userId, roleOk := claims[JwtAccessUuid].(string)
        if roleOk == false {
            JSON(w, http.StatusUnprocessableEntity, "unauthorized")
            return
        }
        //Delete the previous Refresh Token
        delErr := g.s.DeleteRefresh(r.Context(), refreshUuid)
        if delErr != nil { //if any goes wrong
            JSON(w, http.StatusUnauthorized, "unauthorized")
            return
        }

        user, err := g.s.LoadUser(r.Context(), userId)
        if err != nil {
            JSON(w, http.StatusForbidden, err.Error())
            return
        }

        //Create new pairs of refresh and access tokens
        ts, createErr := g.s.RefreshToken(user, claims)
        if createErr != nil {
            JSON(w, http.StatusForbidden, createErr.Error())
            return
        }
        //save the token's metadata to redis
        saveErr := g.s.SaveAuth(r.Context(), userId, ts)
        if saveErr != nil {
            JSON(w, http.StatusForbidden, saveErr.Error())
            return
        }

        JSON(w, http.StatusCreated, ts)
    } else {
        JSON(w, http.StatusUnauthorized, "refresh expired")
    }
}

func (g *httpAdapter) Whoami(w http.ResponseWriter, r *http.Request) {
    //If metadata is passed and the tokens valid, delete them from the redis store
    metadata, _ := g.s.ExtractTokenMetadata(r)
    if metadata != nil {

        data := map[string]interface{}{
            "code":    http.StatusOK,
            "message": fmt.Sprintf("hello ModeratorBoard [%s]", metadata.UserId),
        }

        JSON(w, http.StatusOK, data)
    }

    data := map[string]interface{}{
        "code":    http.StatusNotFound,
        "message": fmt.Sprintf("not logged in"),
    }
    JSON(w, http.StatusUnauthorized, data)
}

func (g *httpAdapter) Sessions(w http.ResponseWriter, r *http.Request) {
    //If metadata is passed and the tokens valid, delete them from the redis store
    metadata, _ := g.s.ExtractTokenMetadata(r)
    if metadata != nil {

        data := map[string]interface{}{
            "code":    http.StatusOK,
            "message": fmt.Sprintf("hello ModeratorBoard [%s]", metadata.UserId),
        }

        JSON(w, http.StatusOK, data)
    }

    data := map[string]interface{}{
        "code":    http.StatusNotFound,
        "message": fmt.Sprintf("not logged in"),
    }
    JSON(w, http.StatusUnauthorized, data)
}

func JSON(w http.ResponseWriter, code int, val interface{}) error {

    b, err := json.Marshal(val)

    if err != nil {
        return err
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(code)
    _, err = w.Write(b)
    return err
}

func ShouldBindJSON(r *http.Request, val any) error {
    err := json.NewDecoder(r.Body).Decode(val)
    if err != nil {
        return err
    }
    return nil
}
