package controllers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/Tharoon321/go-events/config"
	"github.com/Tharoon321/go-events/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// CreateEventInput is the request body for creating an event
type CreateEventInput struct {
	Title       string    `json:"title" binding:"required"`
	Description string    `json:"description,omitempty"`
	StartTime   time.Time `json:"start_time,omitempty"`
	EndTime     time.Time `json:"end_time,omitempty"`
}

// UpdateEventInput allows partial updates
type UpdateEventInput struct {
	Title       *string    `json:"title,omitempty"`
	Description *string    `json:"description,omitempty"`
	StartTime   *time.Time `json:"start_time,omitempty"`
	EndTime     *time.Time `json:"end_time,omitempty"`
}

// CreateEvent creates a new event. Requires Auth middleware to set "userID"
func CreateEvent(c *gin.Context) {
	var input CreateEventInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	uidIf, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	creatorHex := uidIf.(string)
	creatorID, err := primitive.ObjectIDFromHex(creatorHex)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}

	event := models.Event{
		ID:          primitive.NewObjectID(),
		Title:       input.Title,
		Description: input.Description,
		CreatorID:   creatorID,
		StartTime:   input.StartTime,
		EndTime:     input.EndTime,
		Attendees:   []primitive.ObjectID{},
		CreatedAt:   time.Now(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := config.DB.Collection("events").InsertOne(ctx, event)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create event"})
		return
	}

	oid := res.InsertedID.(primitive.ObjectID).Hex()
	c.JSON(http.StatusCreated, gin.H{"id": oid})
}

// ListEvents returns all events (no pagination)
func ListEvents(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := config.DB.Collection("events").Find(ctx, bson.M{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not fetch events"})
		return
	}
	defer cursor.Close(ctx)

	events := []models.Event{}
	for cursor.Next(ctx) {
		var ev models.Event
		if err := cursor.Decode(&ev); err == nil {
			events = append(events, ev)
		}
	}

	c.JSON(http.StatusOK, events)
}

// GetEvent fetches a single event by its hex id
func GetEvent(c *gin.Context) {
	idParam := c.Param("id")
	eventID, err := primitive.ObjectIDFromHex(idParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid event id"})
		return
	}

	var ev models.Event
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := config.DB.Collection("events").FindOne(ctx, bson.M{"_id": eventID}).Decode(&ev); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "event not found"})
		return
	}

	c.JSON(http.StatusOK, ev)
}

// UpdateEvent updates an event; only the creator can update
func UpdateEvent(c *gin.Context) {
	idParam := c.Param("id")
	eventID, err := primitive.ObjectIDFromHex(idParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid event id"})
		return
	}

	userIf, _ := c.Get("userID")
	userHex := userIf.(string)
	userID, err := primitive.ObjectIDFromHex(userHex)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var existing models.Event
	if err := config.DB.Collection("events").FindOne(ctx, bson.M{"_id": eventID}).Decode(&existing); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "event not found"})
		return
	}

	// permission check
	if existing.CreatorID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "only creator can modify"})
		return
	}

	var input UpdateEventInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	update := bson.M{}
	if input.Title != nil {
		update["title"] = *input.Title
	}
	if input.Description != nil {
		update["description"] = *input.Description
	}
	if input.StartTime != nil {
		update["start_time"] = *input.StartTime
	}
	if input.EndTime != nil {
		update["end_time"] = *input.EndTime
	}

	if len(update) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no fields to update"})
		return
	}

	_, err = config.DB.Collection("events").UpdateByID(ctx, eventID, bson.M{"$set": update})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed"})
		return
	}

	c.Status(http.StatusNoContent)
}

// DeleteEvent deletes an event; only the creator can delete
func DeleteEvent(c *gin.Context) {
	idParam := c.Param("id")
	eventID, err := primitive.ObjectIDFromHex(idParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid event id"})
		return
	}

	userIf, _ := c.Get("userID")
	userHex := userIf.(string)
	userID, err := primitive.ObjectIDFromHex(userHex)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var existing models.Event
	if err := config.DB.Collection("events").FindOne(ctx, bson.M{"_id": eventID}).Decode(&existing); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "event not found"})
		return
	}

	if existing.CreatorID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "only creator can delete"})
		return
	}

	_, err = config.DB.Collection("events").DeleteOne(ctx, bson.M{"_id": eventID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete failed"})
		return
	}

	c.Status(http.StatusNoContent)
}

// RegisterForEvent registers the authenticated user as an attendee.
// Uses $addToSet to avoid duplicate registrations.
func RegisterForEvent(c *gin.Context) {
	idParam := c.Param("id")
	eventID, err := primitive.ObjectIDFromHex(idParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid event id"})
		return
	}

	userIf, _ := c.Get("userID")
	userHex := userIf.(string)
	userID, err := primitive.ObjectIDFromHex(userHex)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	update := bson.M{"$addToSet": bson.M{"attendees": userID}}
	_, err = config.DB.Collection("events").UpdateByID(ctx, eventID, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not register"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "registered"})
}
