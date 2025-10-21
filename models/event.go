package models

import (
  "time"
  "go.mongodb.org/mongo-driver/bson/primitive"
)


type Event struct {
  ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
  Title       string             `bson:"title" json:"title"`
  Description string             `bson:"description" json:"description"`
  CreatorID   primitive.ObjectID `bson:"creator_id" json:"creator_id"`
  StartTime   time.Time          `bson:"start_time" json:"start_time"`
  EndTime     time.Time          `bson:"end_time" json:"end_time"`
  Attendees   []primitive.ObjectID `bson:"attendees,omitempty" json:"attendees,omitempty"`
  CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
}
