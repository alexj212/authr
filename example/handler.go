package main

import (
    "authr"
    "fmt"
    "github.com/gin-gonic/gin"
    "net/http"
)

// ProfileHandler struct
type profileHandler struct {
    rd authr.AuthService
    tk authr.TokenInterface
}

func NewProfile(rd authr.AuthService, tk authr.TokenInterface) *profileHandler {
    return &profileHandler{rd: rd, tk: tk}
}

type Todo struct {
    UserID string `json:"user_id"`
    Title  string `json:"title"`
    Body   string `json:"body"`
}

func (h *profileHandler) CreateTodo(c *gin.Context) {
    var td Todo
    if err := c.ShouldBindJSON(&td); err != nil {
        c.JSON(http.StatusUnprocessableEntity, "invalid json")
        return
    }
    metadata, err := h.tk.ExtractTokenMetadata(c.Request)
    if err != nil {
        c.JSON(http.StatusUnauthorized, "unauthorized")
        return
    }
    authInfo, err := h.rd.FetchAuth(c, metadata.TokenUuid)
    if err != nil {
        c.JSON(http.StatusUnauthorized, "unauthorized")
        return
    }

    fmt.Printf("CreateTodo\n")
    for k, v := range metadata.Claims {
        fmt.Printf("claims[%v] = %v\n", k, v)
    }

    td.UserID = authInfo.UserId

    //you can proceed to save the  to a database

    c.JSON(http.StatusCreated, td)
}

func (h *profileHandler) PublicContent(c *gin.Context) {
    var authInfo *authr.AuthTokens
    metadata, err := h.tk.ExtractTokenMetadata(c.Request)
    if err == nil {
        authInfo, err = h.rd.FetchAuth(c, metadata.TokenUuid)
    }

    if authInfo == nil {
        data := gin.H{
            "code":    http.StatusOK,
            "message": fmt.Sprintf("hello PublicContent"),
        }
        c.JSON(http.StatusOK, data)
        return
    }

    data := gin.H{
        "code":    http.StatusOK,
        "message": fmt.Sprintf("hello PublicContent [%s]", authInfo.UserId),
    }
    fmt.Printf("PublicContent userId: %v\n", authInfo.UserId)

    if metadata != nil {
        fmt.Printf("PublicContent roles: %v\n", metadata.Role)
        for k, v := range metadata.Claims {
            data[k] = v
        }
    }
    c.JSON(http.StatusOK, data)
}

func (h *profileHandler) UserBoard(c *gin.Context) {
    metadata, err := h.tk.ExtractTokenMetadata(c.Request)
    if err != nil {
        c.JSON(http.StatusUnauthorized, "unauthorized")
        return
    }
    authInfo, err := h.rd.FetchAuth(c, metadata.TokenUuid)
    if err != nil {
        c.JSON(http.StatusUnauthorized, "unauthorized")
        return
    }

    data := gin.H{
        "code":    http.StatusOK,
        "message": fmt.Sprintf("hello UserBoard [%s]", authInfo.UserId),
    }
    roles := metadata.Claims[authr.JwtRole]
    fmt.Printf("UserBoard roles: %v\n", roles)
    fmt.Printf("UserBoard roles: %v\n", metadata.Role)
    fmt.Printf("UserBoard userId: %v\n", authInfo.UserId)
    for k, v := range metadata.Claims {
        data[k] = v
    }

    c.JSON(http.StatusOK, data)
}

func (h *profileHandler) ModeratorBoard(c *gin.Context) {
    metadata, err := h.tk.ExtractTokenMetadata(c.Request)
    if err != nil {
        c.JSON(http.StatusUnauthorized, "unauthorized")
        return
    }
    authInfo, err := h.rd.FetchAuth(c, metadata.TokenUuid)
    if err != nil {
        c.JSON(http.StatusUnauthorized, "unauthorized")
        return
    }

    roles := metadata.Claims[authr.JwtRole]
    fmt.Printf("ModeratorBoard roles: %v\n", roles)
    fmt.Printf("ModeratorBoard roles: %v\n", metadata.Role)
    fmt.Printf("ModeratorBoard userId: %v\n", authInfo.UserId)
    data := gin.H{
        "code":    http.StatusOK,
        "message": fmt.Sprintf("hello ModeratorBoard [%s]", authInfo.UserId),
    }
    for k, v := range metadata.Claims {
        data[k] = v
    }

    c.JSON(http.StatusOK, data)

}

func (h *profileHandler) AdminBoard(c *gin.Context) {
    metadata, err := h.tk.ExtractTokenMetadata(c.Request)
    if err != nil {
        c.JSON(http.StatusUnauthorized, "unauthorized")
        return
    }
    authInfo, err := h.rd.FetchAuth(c, metadata.TokenUuid)
    if err != nil {
        c.JSON(http.StatusUnauthorized, "unauthorized")
        return
    }
    data := gin.H{
        "code":    http.StatusOK,
        "message": fmt.Sprintf("hello AdminBoard [%s]", authInfo.UserId),
    }
    roles := metadata.Claims[authr.JwtRole]
    fmt.Printf("AdminBoard roles: %v\n", roles)
    fmt.Printf("AdminBoard roles: %v\n", metadata.Role)
    fmt.Printf("AdminBoard userId: %v\n", authInfo.UserId)
    for k, v := range metadata.Claims {
        data[k] = v
    }

    c.JSON(http.StatusOK, data)
}
