package controllers

import (
	"context"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
	"fmt"
	"go.mongodb.org/mongo-driver/mongo"  

	"github.com/gin-gonic/gin"
	"github.com/Tharoon321/go-events/config"
	"github.com/Tharoon321/go-events/models"
	"github.com/Tharoon321/go-events/utils"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

// RegisterInput request body for registration
type RegisterInput struct {
	Name     string `json:"name" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
	Role     string `json:"role" binding:"required"` // "creator" or "attendee"
}

// LoginInput request body for login
type LoginInput struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// ForgotPasswordInput
type ForgotPasswordInput struct {
	Email string `json:"email" binding:"required,email"`
}

// ResetPasswordInput
type ResetPasswordInput struct {
	Email       string `json:"email" binding:"required,email"`
	OTP         string `json:"otp" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=6"`
}

// Register handler: creates a new user
func Register(c *gin.Context) {
	var input RegisterInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// create short-lived ctx for DB operations
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	usersCol := config.DB.Collection("users")

	// check if user already exists
	var existing models.User
	err := usersCol.FindOne(ctx, bson.M{"email": input.Email}).Decode(&existing)
	if err == nil {
		// user found -> duplicate
		c.JSON(http.StatusConflict, gin.H{"error": "email already registered"})
		return
	}
	if err != nil && err != mongo.ErrNoDocuments {
		// unexpected DB error
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}

	// hash the password before saving
	hash, err := utils.HashPassword(input.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
		return
	}

	now := time.Now().UTC()
	newUser := models.User{
		ID:        primitive.NewObjectID(),
		Name:      input.Name,
		Email:     input.Email,
		Password:  hash,
		Role:      input.Role,
		CreatedAt: now,
	}

	_, err = usersCol.InsertOne(ctx, newUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "user registered"})
}

// Login handler: authenticates and returns JWT
func Login(c *gin.Context) {
	var input LoginInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// use same DB reference style as Register
	usersCol := config.DB.Collection("users")

	var user models.User
	err := usersCol.FindOne(ctx, bson.M{"email": input.Email}).Decode(&user)
	if err != nil {
		// helpful debug log for local testing
		log.Printf("Login: user not found email=%s err=%v\n", input.Email, err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// debug: show hashed password length (do NOT print actual hash in production)
	log.Printf("Login: found user email=%s hashedLen=%d\n", user.Email, len(user.Password))

	// verify password (hash, plain)
	if err := utils.CheckPassword(user.Password, input.Password); err != nil {
		log.Printf("Login: password mismatch for email=%s err=%v\n", input.Email, err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// generate JWT, user.ID.Hex() is correct for Mongo ObjectID
	token, err := utils.GenerateJWT(user.ID.Hex(), user.Role)
	if err != nil {
		log.Printf("Login: jwt generation failed err=%v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"user": gin.H{
			"id":    user.ID.Hex(),
			"name":  user.Name,
			"email": user.Email,
			"role":  user.Role,
		},
	})
}


// utility: generate numeric OTP of n digits
func generateNumericOTP(n int) string {
	// simple numeric OTP; not cryptographically strong but fine for learning
	// prefer crypto/rand for stronger OTPs
	max := 1
	for i := 0; i < n; i++ {
		max *= 10
	}
	num := time.Now().UnixNano() % int64(max)
	format := "%0" + strconv.Itoa(n) + "d"
	return fmt.Sprintf(format, num)
}

// ForgotPassword: generate OTP, save hashed OTP & expiry, send email or log
func ForgotPassword(c *gin.Context) {
	var input ForgotPasswordInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	users := config.DB.Collection("users")

	var user models.User
	if err := users.FindOne(ctx, bson.M{"email": input.Email}).Decode(&user); err != nil {
		// For security, don't reveal whether user exists — respond with success message
		c.JSON(http.StatusOK, gin.H{"message": "if that email exists, an OTP has been sent"})
		return
	}

	otpTTL := 10 // minutes default
	if val := os.Getenv("OTP_TTL_MIN"); val != "" {
		if mins, err := strconv.Atoi(val); err == nil {
			otpTTL = mins
		}
	}

	// generate OTP (6 digits)
	otp := utils.GenerateOTP(6) // We'll implement GenerateOTP in utils (see note)
	// hash OTP before storing
	hashedOTP, err := bcrypt.GenerateFromPassword([]byte(otp), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate otp"})
		return
	}

	update := bson.M{
		"$set": bson.M{
			"reset_otp":     string(hashedOTP),
			"reset_otp_exp": time.Now().Add(time.Duration(otpTTL) * time.Minute),
		},
	}

	_, err = users.UpdateByID(ctx, user.ID, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not store otp"})
		return
	}

	// Try to send email — call utils.SendMail (implement in utils/mail.go).
	subject := "Your password reset OTP"
	body := "Your OTP is: " + otp + "\nThis code expires in " + strconv.Itoa(otpTTL) + " minutes."

	if err := utils.SendMail(user.Email, subject, body); err != nil {
		// fallback: log OTP to console (useful in development)
		log.Println("Failed to send email, OTP (dev-only):", otp, "error:", err)
	} else {
		log.Println("Sent OTP email to", user.Email)
	}

	// Always return generic message
	c.JSON(http.StatusOK, gin.H{"message": "if that email exists, an OTP has been sent"})
}

// ResetPassword: verify OTP and set new password
func ResetPassword(c *gin.Context) {
	var input ResetPasswordInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	users := config.DB.Collection("users")

	var user models.User
	if err := users.FindOne(ctx, bson.M{"email": input.Email}).Decode(&user); err != nil {
		// generic response
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid OTP or email"})
		return
	}

	// Check OTP exists and not expired
	if user.ResetOTP == "" || user.ResetOTPExp.Before(time.Now()) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired OTP"})
		return
	}

	// Compare provided OTP with hashed stored OTP
	if err := bcrypt.CompareHashAndPassword([]byte(user.ResetOTP), []byte(input.OTP)); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid OTP"})
		return
	}

	// Hash new password
	newHash, err := utils.HashPassword(input.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not hash password"})
		return
	}

	update := bson.M{
		"$set": bson.M{
			"password_hash": newHash,
		},
		"$unset": bson.M{
			"reset_otp":     "",
			"reset_otp_exp": "",
		},
	}

	_, err = users.UpdateByID(ctx, user.ID, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not reset password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "password reset successful"})
}
