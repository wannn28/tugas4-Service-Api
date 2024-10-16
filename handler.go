package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte("your_secret_key_here") // Change with your own secret key

// Authenticate handles user authentication and returns a JWT token
func Authenticate(c echo.Context) error {
	db := c.Get("db").(*sql.DB)
	var credentials AuthDTO
	if err := c.Bind(&credentials); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": err.Error()})
	}

	// Fetch user from database
	var user User
	row := db.QueryRow("SELECT id, password_hash, role FROM users WHERE username = ?", credentials.UserName)
	err := row.Scan(&user.ID, &user.PasswordHash, &user.Role)
	if err != nil {
		fmt.Println("Error fetching user:", err)
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Invalid username or password"})
	}

	// Compare passwords
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(credentials.PassWord)); err != nil {
		fmt.Println("Password mismatch:", err)
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Invalid username or password"})
	}

	// Create JWT token
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["user_id"] = user.ID
	claims["username"] = credentials.UserName
	claims["role"] = user.Role
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix()

	t, err := token.SignedString(jwtKey)
	if err != nil {
		fmt.Println("Error signing token:", err)
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, echo.Map{"token": t})
}

// CheckUserRole checks if the user has the required role
func CheckUserRole(role string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			userTokenInterface := c.Get("user")
			if userTokenInterface == nil {
				fmt.Println("No user token found in context")
				return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Invalid token"})
			}
			userToken, ok := userTokenInterface.(*jwt.Token)
			if !ok {
				fmt.Println("User token in context is not of type *jwt.Token")
				return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Invalid token"})
			}
			claims, ok := userToken.Claims.(jwt.MapClaims)
			if !ok {
				fmt.Println("Failed to assert token claims as jwt.MapClaims")
				return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Invalid token claims"})
			}
			userRole, ok := claims["role"].(string)
			if !ok {
				fmt.Println("Role not found or not a string in token claims")
				return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Invalid role in token"})
			}
			if userRole != role {
				return c.JSON(http.StatusForbidden, echo.Map{"error": "Access forbidden"})
			}
			return next(c)
		}
	}
}

// GetTasks retrieves tasks for the authenticated user
func GetTasks(c echo.Context) error {
	db := c.Get("db").(*sql.DB)
	userToken := c.Get("user").(*jwt.Token)
	claims := userToken.Claims.(jwt.MapClaims)
	userID := int(claims["user_id"].(float64))

	rows, err := db.Query("SELECT id, name, is_done, user_id FROM tasks WHERE user_id = ?", userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
	}
	defer rows.Close()

	var tasks []Task
	for rows.Next() {
		var task Task
		if err := rows.Scan(&task.ID, &task.Name, &task.IsDone, &task.UserID); err != nil {
			return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
		}
		tasks = append(tasks, task)
	}

	return c.JSON(http.StatusOK, tasks)
}

// CreateTask creates a new task for the authenticated user
func CreateTask(c echo.Context) error {
	db := c.Get("db").(*sql.DB)
	var dto CreateTaskDTO
	if err := c.Bind(&dto); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": err.Error()})
	}

	userToken := c.Get("user").(*jwt.Token)
	claims := userToken.Claims.(jwt.MapClaims)
	userID := int(claims["user_id"].(float64))

	_, err := db.Exec("INSERT INTO tasks (name, is_done, user_id) VALUES (?, ?, ?)",
		dto.Name, false, userID)
	if err != nil {
		fmt.Println("Error inserting task:", err)
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, echo.Map{"message": "Task created successfully"})
}

// UpdateTask updates an existing task for the authenticated user
func UpdateTask(c echo.Context) error {
	db := c.Get("db").(*sql.DB)
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid ID"})
	}

	userToken := c.Get("user").(*jwt.Token)
	claims := userToken.Claims.(jwt.MapClaims)
	userID := int(claims["user_id"].(float64))

	// Verify ownership
	var ownerID int
	err = db.QueryRow("SELECT user_id FROM tasks WHERE id = ?", id).Scan(&ownerID)
	if err != nil {
		fmt.Println("Error fetching task owner:", err)
		return c.JSON(http.StatusNotFound, echo.Map{"error": "Task not found"})
	}
	if ownerID != userID {
		return c.JSON(http.StatusForbidden, echo.Map{"error": "Access forbidden"})
	}

	var dto UpdateTaskDTO
	if err := c.Bind(&dto); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": err.Error()})
	}

	_, err = db.Exec("UPDATE tasks SET name = ?, is_done = ? WHERE id = ?",
		dto.Name, dto.IsDone, id)
	if err != nil {
		fmt.Println("Error updating task:", err)
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, echo.Map{"message": "Task updated successfully"})
}

// DeleteTask deletes a task for the authenticated user
func DeleteTask(c echo.Context) error {
	db := c.Get("db").(*sql.DB)
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid ID"})
	}

	userToken := c.Get("user").(*jwt.Token)
	claims := userToken.Claims.(jwt.MapClaims)
	userID := int(claims["user_id"].(float64))

	// Verify ownership
	var ownerID int
	err = db.QueryRow("SELECT user_id FROM tasks WHERE id = ?", id).Scan(&ownerID)
	if err != nil {
		fmt.Println("Error fetching task owner:", err)
		return c.JSON(http.StatusNotFound, echo.Map{"error": "Task not found"})
	}
	if ownerID != userID {
		return c.JSON(http.StatusForbidden, echo.Map{"error": "Access forbidden"})
	}

	_, err = db.Exec("DELETE FROM tasks WHERE id = ?", id)
	if err != nil {
		fmt.Println("Error deleting task:", err)
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, echo.Map{"message": "Task deleted successfully"})
}

// GetAllUsers retrieves all users (Admin only)
func GetAllUsers(c echo.Context) error {
	db := c.Get("db").(*sql.DB)
	rows, err := db.Query("SELECT id, username, role FROM users")
	if err != nil {
		fmt.Println("Error fetching users:", err)
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.UserName, &user.Role); err != nil {
			fmt.Println("Error scanning user:", err)
			return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
		}
		users = append(users, user)
	}

	return c.JSON(http.StatusOK, users)
}

// AddUser creates a new user (Admin only)
func AddUser(c echo.Context) error {
	db := c.Get("db").(*sql.DB)
	var dto RegisterUserDTO
	if err := c.Bind(&dto); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": err.Error()})
	}

	// Validate role
	if dto.Role != "Editor" && dto.Role != "Admin" {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid role"})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(dto.PassWord), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("Error hashing password:", err)
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
	}

	_, err = db.Exec("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
		dto.UserName, string(hashedPassword), dto.Role)
	if err != nil {
		fmt.Println("Error inserting user:", err)
		if mysqlErr, ok := err.(*mysql.MySQLError); ok && mysqlErr.Number == 1062 {
			return c.JSON(http.StatusBadRequest, echo.Map{"error": "Username already exists"})
		}
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, echo.Map{"message": "User created successfully"})
}

// UpdateUser updates an existing user (Admin only)
func UpdateUser(c echo.Context) error {
	db := c.Get("db").(*sql.DB)
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid ID"})
	}

	var dto RegisterUserDTO
	if err := c.Bind(&dto); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": err.Error()})
	}

	// Validate role
	if dto.Role != "Editor" && dto.Role != "Admin" {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid role"})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(dto.PassWord), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("Error hashing password:", err)
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
	}

	_, err = db.Exec("UPDATE users SET username = ?, password_hash = ?, role = ? WHERE id = ?",
		dto.UserName, string(hashedPassword), dto.Role, id)
	if err != nil {
		fmt.Println("Error updating user:", err)
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, echo.Map{"message": "User updated successfully"})
}

// RemoveUser deletes a user (Admin only)
func RemoveUser(c echo.Context) error {
	db := c.Get("db").(*sql.DB)
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid ID"})
	}

	_, err = db.Exec("DELETE FROM users WHERE id = ?", id)
	if err != nil {
		fmt.Println("Error deleting user:", err)
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, echo.Map{"message": "User deleted successfully"})
}
