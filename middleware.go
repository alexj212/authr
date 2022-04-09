package authr

import (
    "github.com/gin-gonic/gin"
    "net/http"
)

func TokenAuthMiddleware(tk TokenInterface) gin.HandlerFunc {
    return func(c *gin.Context) {
        err := tk.TokenValid(c.Request)
        if err != nil {
            c.JSON(http.StatusUnauthorized, "unauthorized")
            c.Abort()
            return
        }
        c.Next()
    }
}
