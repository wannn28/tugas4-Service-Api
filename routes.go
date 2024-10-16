package main

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// Route registers all available routes
func Route(e *echo.Echo) {
	// Public routes
	e.POST("/auth", Authenticate)

	// Group for authenticated routes
	protected := e.Group("")
	protected.Use(middleware.JWTWithConfig(middleware.JWTConfig{
		SigningKey: jwtKey,
	}))

	// Routes for Contributors (and Admins)
	editor := protected.Group("/tasks")
	editor.Use(CheckUserRole("Editor"))
	editor.GET("", GetTasks)
	editor.POST("", CreateTask)
	editor.PUT("/:id", UpdateTask)
	editor.DELETE("/:id", DeleteTask)

	// Routes for Admins
	admin := protected.Group("/users")
	admin.Use(CheckUserRole("Admin"))
	admin.GET("", GetAllUsers)
	admin.POST("", AddUser)
	admin.PUT("/:id", UpdateUser)
	admin.DELETE("/:id", RemoveUser)
}
