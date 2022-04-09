package authr

import (
    "fmt"
    "github.com/dgrijalva/jwt-go"
    "github.com/gin-gonic/gin"
    "net/http"
)

func (s *service) Login(c *gin.Context) {

    metadata, _ := s.ts.ExtractTokenMetadata(c.Request)
    if metadata != nil {
        deleteErr := s.DeleteTokens(c, metadata)
        if deleteErr != nil {
            c.JSON(http.StatusBadRequest, deleteErr.Error())
            return
        }
    }

    var loginArgs LoginParams
    if err := c.ShouldBindJSON(&loginArgs); err != nil {
        c.JSON(http.StatusUnprocessableEntity, "Invalid json provided")
        return
    }

    user, err := s.LoginUser(c, &loginArgs)
    if err != nil {
        c.JSON(http.StatusUnprocessableEntity, err.Error())
        return
    }

    //compare the user from the request, with the one we defined:
    if user == nil {
        c.JSON(http.StatusUnauthorized, "Please provide valid login details")
        return
    }
    ts, err := s.ts.CreateToken(user)
    if err != nil {
        c.JSON(http.StatusUnprocessableEntity, err.Error())
        return
    }
    saveErr := s.SaveAuth(c, user.ID, ts)
    if saveErr != nil {
        c.JSON(http.StatusUnprocessableEntity, saveErr.Error())
        return
    }

    c.JSON(http.StatusOK, ts)
}

func (s *service) Register(c *gin.Context) {

    metadata, _ := s.ts.ExtractTokenMetadata(c.Request)
    if metadata != nil {
        c.JSON(http.StatusUnauthorized, "unable to register - user is logged in")
        return
    }

    var regArgs RegistrationParams
    if err := c.ShouldBindJSON(&regArgs); err != nil {
        c.JSON(http.StatusUnprocessableEntity, "Invalid json provided")
        return
    }

    user, err := s.RegisterUser(c, &regArgs)
    if err != nil {
        c.JSON(http.StatusUnprocessableEntity, "error occurred")
        return
    }

    if user == nil {
        c.JSON(http.StatusUnauthorized, "Please provide valid registration details")
        return
    }

    ts, err := s.ts.CreateToken(user)
    if err != nil {
        c.JSON(http.StatusUnprocessableEntity, err.Error())
        return
    }
    saveErr := s.SaveAuth(c, user.ID, ts)
    if saveErr != nil {
        c.JSON(http.StatusUnprocessableEntity, saveErr.Error())
        return
    }

    c.JSON(http.StatusOK, ts)
}

func (s *service) Logout(c *gin.Context) {
    //If metadata is passed and the tokens valid, delete them from the redis store
    metadata, _ := s.ts.ExtractTokenMetadata(c.Request)
    if metadata != nil {
        deleteErr := s.DeleteTokens(c, metadata)
        if deleteErr != nil {
            c.JSON(http.StatusBadRequest, deleteErr.Error())
            return
        }
    }
    c.JSON(http.StatusOK, "Successfully logged out")
}

func (s *service) Refresh(c *gin.Context) {
    mapToken := map[string]string{}
    if err := c.ShouldBindJSON(&mapToken); err != nil {
        c.JSON(http.StatusUnprocessableEntity, err.Error())
        return
    }
    refreshToken := mapToken["refresh_token"]

    //verify the token
    token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return []byte(s.ts.RefreshSecret()), nil
    })
    //if there is an error, the token must have expired
    if err != nil {
        c.JSON(http.StatusUnauthorized, "Refresh token expired")
        return
    }
    //is token valid?
    if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
        c.JSON(http.StatusUnauthorized, err)
        return
    }
    //Since token is valid, get the uuid:
    claims, ok := token.Claims.(jwt.MapClaims) //the token claims should conform to MapClaims
    if ok && token.Valid {
        refreshUuid, ok := claims[JwtRefreshUuid].(string) //convert the interface to string
        if !ok {
            c.JSON(http.StatusUnprocessableEntity, err)
            return
        }
        userId, roleOk := claims[JwtAccessUuid].(string)
        if roleOk == false {
            c.JSON(http.StatusUnprocessableEntity, "unauthorized")
            return
        }
        //Delete the previous Refresh Token
        delErr := s.DeleteRefresh(c, refreshUuid)
        if delErr != nil { //if any goes wrong
            c.JSON(http.StatusUnauthorized, "unauthorized")
            return
        }

        user, err := s.LoadUser(c, userId)
        if err != nil {
            c.JSON(http.StatusForbidden, err.Error())
            return
        }

        //Create new pairs of refresh and access tokens
        ts, createErr := s.ts.RefreshToken(user, claims)
        if createErr != nil {
            c.JSON(http.StatusForbidden, createErr.Error())
            return
        }
        //save the token's metadata to redis
        saveErr := s.SaveAuth(c, userId, ts)
        if saveErr != nil {
            c.JSON(http.StatusForbidden, saveErr.Error())
            return
        }

        c.JSON(http.StatusCreated, ts)
    } else {
        c.JSON(http.StatusUnauthorized, "refresh expired")
    }
}

func (s *service) Whoami(c *gin.Context) {
    //If metadata is passed and the tokens valid, delete them from the redis store
    metadata, _ := s.ts.ExtractTokenMetadata(c.Request)
    if metadata != nil {

        data := gin.H{
            "code":    http.StatusOK,
            "message": fmt.Sprintf("hello ModeratorBoard [%s]", metadata.UserId),
        }

        c.JSON(http.StatusOK, data)
    }

    data := gin.H{
        "code":    http.StatusNotFound,
        "message": fmt.Sprintf("not logged in"),
    }
    c.JSON(http.StatusUnauthorized, data)
}

func (s *service) Sessions(c *gin.Context) {
    //If metadata is passed and the tokens valid, delete them from the redis store
    metadata, _ := s.ts.ExtractTokenMetadata(c.Request)
    if metadata != nil {

        data := gin.H{
            "code":    http.StatusOK,
            "message": fmt.Sprintf("hello ModeratorBoard [%s]", metadata.UserId),
        }

        c.JSON(http.StatusOK, data)
    }

    data := gin.H{
        "code":    http.StatusNotFound,
        "message": fmt.Sprintf("not logged in"),
    }
    c.JSON(http.StatusUnauthorized, data)
}
