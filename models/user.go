package models

import "time"

import "go.mongodb.org/mongo-driver/bson/primitive"

// User is a typical user model for this project.
// Adjust tags/fields if you want to hide password from JSON, etc.
type User struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name         string             `bson:"name" json:"name"`
	Email        string             `bson:"email" json:"email"`
	Password     string             `bson:"password_hash" json:"-"`            // hashed password; omit from JSON output
	Role         string             `bson:"role" json:"role"`            // "creator" or "attendee"
	ResetOTP     string             `bson:"reset_otp,omitempty" json:"-"` // hashed otp (optional)
	ResetOTPExp  time.Time          `bson:"reset_otp_exp,omitempty" json:"-"`
	CreatedAt    time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt    time.Time          `bson:"updated_at,omitempty" json:"updated_at,omitempty"`
}

