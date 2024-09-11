package main

import (
	"git-jwt/controllers"
	"git-jwt/initializers"
	middleware "git-jwt/middlewares"

	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDb()
	initializers.SyncDatabase()
}

func main() {
	gin.ForceConsoleColor()
	r := gin.Default()
	r.POST("/signup", controllers.Signup)
	r.POST("/login", controllers.Login)
	r.POST("/refresh-token", controllers.RefreshToken)
	r.GET("/validate", middleware.RequireAuth, controllers.Validate)

	r.Run()
}
