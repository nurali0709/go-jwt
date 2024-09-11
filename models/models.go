package models

import "gorm.io/gorm"

type User struct{
 gorm.Model
 Email string `gorm:"unique"`
 Password string
}


type Token struct {
	gorm.Model
	UserID uint
	AccessToken string
	RefreshHash string
	IpAddress string
}
