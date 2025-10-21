package models

import (
	"time"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Role string

const (
	RoleCreator  Role = "creator"
	RoleAttendee Role = "attendee"
)

type User struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name         string             `bson:"name" json:"name"`
	Email        string             `bson:"email" json:"email"`
	PasswordHash string             `bson:"password_hash" json:"-"`
	Role         Role               `bson:"role" json:"role"`
	CreatedAt    time.Time          `bson:"created_at" json:"created_at"`
	ResetOTP     string             `bson:"reset_otp,omitempty" json:"-"`
	ResetOTPExp  time.Time          `bson:"reset_otp_exp,omitempty" json:"-"`
}
