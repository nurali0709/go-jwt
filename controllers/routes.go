package controllers

import (
	"crypto/rand"
	"encoding/base64"
	"git-jwt/initializers"
	"git-jwt/models"
	"net/http"
    "fmt"
	"os"
	"time"
    "gorm.io/gorm"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func Signup(c *gin.Context) {
	var body struct {
		Email    string
		Password string
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to hash password.",
		})
		return
	}

	user := models.User{Email: body.Email, Password: string(hash)}
	result := initializers.DB.Create(&user)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create user.",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

func Login(c *gin.Context) {
	var body struct {
		Email    string
		Password string
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})
		return
	}

	var user models.User
	initializers.DB.First(&user, "email = ?", body.Email)

	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid email or password",
		})
		return
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid email or password",
		})
		return
	}

	tokenString, err := generateJWT(user.ID, c.ClientIP())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create token",
		})
		return
	}

	refreshToken := generateRefreshToken()

	hashedRefreshToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to hash refresh token",
		})
		return
	}

	token := models.Token{
		UserID:      user.ID,
		AccessToken: tokenString,
		RefreshHash: string(hashedRefreshToken),
		IpAddress:   c.ClientIP(),
	}

	initializers.DB.Create(&token)

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", tokenString, 3600*24*30, "", "", false, true)
	c.JSON(http.StatusOK, gin.H{
		"refresh_token": base64.StdEncoding.EncodeToString([]byte(refreshToken)),
	})
}

func RefreshToken(c *gin.Context) {
    var body struct {
        RefreshToken string
    }
    if c.Bind(&body) != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Failed to read body",
        })
        return
    }

    decodedToken, err := base64.StdEncoding.DecodeString(body.RefreshToken)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid refresh token"})
        return
    }

    tokenString, err := c.Cookie("Authorization")
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{
            "error": "Authorization token not found",
        })
        return
    }

    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return []byte(os.Getenv("SECRET")), nil
    })

    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{
            "error": "Invalid authorization token",
        })
        return
    }

    var userID uint
    if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
        userID = uint(claims["sub"].(float64))
    } else {
        c.JSON(http.StatusUnauthorized, gin.H{
            "error": "Invalid token claims",
        })
        return
    }

    var tokenRecord models.Token
    err = initializers.DB.Where("user_id = ? AND ip_address = ?", userID, c.ClientIP()).First(&tokenRecord).Error
    if err != nil {
        if err == gorm.ErrRecordNotFound {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Token not found"})
        } else {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
        }
        return
    }

    err = bcrypt.CompareHashAndPassword([]byte(tokenRecord.RefreshHash), decodedToken)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{
            "error": "Invalid refresh token",
        })
        return
    }

    newAccessToken, err := generateJWT(userID, c.ClientIP())
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{
            "error": "Failed to create new access token",
        })
        return
    }

    tokenRecord.AccessToken = newAccessToken
    tokenRecord.IpAddress = c.ClientIP()
    initializers.DB.Save(&tokenRecord)

    c.JSON(http.StatusOK, gin.H{
        "access_token": newAccessToken,
    })
}
func Validate(c *gin.Context) {
	user, _ := c.Get("user")
	c.JSON(http.StatusOK, gin.H{
		"message": user,
	})
}

func generateJWT(userID uint, ipAddress string) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
		"ip":  ipAddress,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString([]byte(os.Getenv("SECRET")))
}

func generateRefreshToken() string {
	refreshToken := make([]byte, 32)
	rand.Read(refreshToken)
	return base64.StdEncoding.EncodeToString(refreshToken)
}
