package main

// CreateTaskDTO for creating a new task
type CreateTaskDTO struct {
	Name string `json:"name" binding:"required"`
}

// UpdateTaskDTO for updating an existing task
type UpdateTaskDTO struct {
	Name   string `json:"name"`
	IsDone bool   `json:"is_done"`
}

// AuthDTO for user authentication
type AuthDTO struct {
	UserName string `json:"username" binding:"required"`
	PassWord string `json:"password" binding:"required"`
}

// RegisterUserDTO for creating a new user
type RegisterUserDTO struct {
	UserName string `json:"username" binding:"required"`
	PassWord string `json:"password" binding:"required"`
	Role     string `json:"role" binding:"required"` // Should be "Editor" or "Admin"
}
