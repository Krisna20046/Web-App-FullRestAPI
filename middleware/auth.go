package middleware

import (
	"a21hc3NpZ25tZW50/model"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

func Auth() gin.HandlerFunc {
	return gin.HandlerFunc(func(ctx *gin.Context) {
		// Mengecek keberadaan cookie session_token
		cookie, err := ctx.Request.Cookie("session_token")
		if err != nil || cookie.Value == "" {
			// Cookie session_token tidak ada atau kosong, mengembalikan respon HTTP dengan status code 401 jika Content-Type "application/json" atau melakukan redirect ke halaman login jika tidak
			if ctx.GetHeader("Content-Type") == "application/json" {
				ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
				ctx.Abort()
				return
			} else {
				ctx.Redirect(http.StatusSeeOther, "/login")
				ctx.Abort()
				return
			}
		}

		// Parsing JWT token dari cookie session_token
		tokenString := cookie.Value
		claims := &model.Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return model.JwtKey, nil
		})

		if err != nil {
			// Parsing token gagal, mengembalikan respon HTTP dengan status code 401 atau 400 tergantung jenis error yang terjadi
			if err == jwt.ErrSignatureInvalid {
				ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
				ctx.Abort()
				return
			}
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
			ctx.Abort()
			return
		}

		if !token.Valid {
			// Token tidak valid, mengembalikan respon HTTP dengan status code 401
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			ctx.Abort()
			return
		}

		// Menyimpan nilai UserID dari claims ke dalam context dengan key "id"
		ctx.Set("id", claims.UserID)

		// Memanggil handler atau endpoint selanjutnya
		ctx.Next()
	})
}
