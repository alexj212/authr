package main

import (
    "fmt"
    "github.com/alexj212/authr"
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

func (h *profileHandler) CreateTodo(w http.ResponseWriter, r *http.Request) {
    var td Todo
    if err := authr.ShouldBindJSON(r, &td); err != nil {
        authr.JSON(w, http.StatusUnprocessableEntity, "invalid json")
        return
    }
    metadata, err := h.tk.ExtractTokenMetadata(r)
    if err != nil {
        authr.JSON(w, http.StatusUnauthorized, "unauthorized")
        return
    }
    authInfo, err := h.rd.FetchAuth(r.Context(), metadata.TokenUuid)
    if err != nil {
        authr.JSON(w, http.StatusUnauthorized, "unauthorized")
        return
    }

    fmt.Printf("CreateTodo\n")
    for k, v := range metadata.Claims {
        fmt.Printf("claims[%v] = %v\n", k, v)
    }

    td.UserID = authInfo.UserId

    //you can proceed to save the  to a database

    authr.JSON(w, http.StatusCreated, td)
}

func (h *profileHandler) PublicContent(w http.ResponseWriter, r *http.Request) {
    var authInfo *authr.AuthTokens
    metadata, err := h.tk.ExtractTokenMetadata(r)
    if err == nil {
        authInfo, err = h.rd.FetchAuth(r.Context(), metadata.TokenUuid)
    }

    if authInfo == nil {
        data := gin.H{
            "code":    http.StatusOK,
            "message": fmt.Sprintf("hello PublicContent"),
        }
        authr.JSON(w, http.StatusOK, data)
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
    authr.JSON(w, http.StatusOK, data)
}

func (h *profileHandler) UserBoard(w http.ResponseWriter, r *http.Request) {
    metadata, err := h.tk.ExtractTokenMetadata(r)
    if err != nil {
        authr.JSON(w, http.StatusUnauthorized, "unauthorized")
        return
    }
    authInfo, err := h.rd.FetchAuth(r.Context(), metadata.TokenUuid)
    if err != nil {
        authr.JSON(w, http.StatusUnauthorized, "unauthorized")
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

    authr.JSON(w, http.StatusOK, data)
}

func (h *profileHandler) ModeratorBoard(w http.ResponseWriter, r *http.Request) {
    metadata, err := h.tk.ExtractTokenMetadata(r)
    if err != nil {
        authr.JSON(w, http.StatusUnauthorized, "unauthorized")
        return
    }
    authInfo, err := h.rd.FetchAuth(r.Context(), metadata.TokenUuid)
    if err != nil {
        authr.JSON(w, http.StatusUnauthorized, "unauthorized")
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

    authr.JSON(w, http.StatusOK, data)

}

func (h *profileHandler) AdminBoard(w http.ResponseWriter, r *http.Request) {
    metadata, err := h.tk.ExtractTokenMetadata(r)
    if err != nil {
        authr.JSON(w, http.StatusUnauthorized, "unauthorized")
        return
    }
    authInfo, err := h.rd.FetchAuth(r.Context(), metadata.TokenUuid)
    if err != nil {
        authr.JSON(w, http.StatusUnauthorized, "unauthorized")
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

    authr.JSON(w, http.StatusOK, data)
}
