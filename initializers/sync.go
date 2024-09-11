package initializers

import "git-jwt/models"

func SyncDatabase(){
 DB.AutoMigrate(&models.User{}, &models.Token{})
}