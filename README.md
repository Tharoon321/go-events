A backend API for managing events — built with Go (Gin Framework),MongoDB Atlas and JWT Authentication.  
It includes secure OTP-based password reset, user management, and event CRUD operations.


Deployed on Render: https://go-events-qkad.onrender.com

Tech Stack Used:

Category	        Technology

Language	        Go (Golang)
Framework	        Gin
Database	        MongoDB Atlas
Authentication	  JWT (JSON Web Token)
Security	        bcrypt + crypto/rand
Email/OTP	        SMTP-based OTP system
Deployment	      Render
Testing	          Postman


👤 User Authentication (JWT)
🔑 OTP-based Password Reset
🗓️ Event CRUD Operations
📅 User Role Management (creator / attendee)
☁️ MongoDB Atlas Integration
🚀 Live Deployed API on Render

| Method | Endpoint                  | Description              | Auth  |
| ------ | --------------------------| ------------------------ | ----  |
| POST   | /api/auth/register        | Register new user        | ❌    |
| POST   | /api/auth/login           | Login user and get JWT   | ❌    |
| POST   | /api/auth/forgot-password | Send OTP to email        | ❌    |
| POST   | /api/auth/reset-password  | Reset password using OTP | ❌    |
| GET    | /api/events               | Get all events           | ✅    |
| POST   | /api/events               | Create a new event       | ✅    |
| GET    | /api/events/:id           | Get specific event       | ✅    |
| PUT    | /api/events/:id           | Update event details     | ✅    |
| DELETE | /api/events/:id           | Delete an event          | ✅    |
