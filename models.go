package main

// User represents a user in the system
type User struct {
    ID           int    `json:"id"`
    UserName     string `json:"username"`
    PasswordHash string `json:"-"`
    Role         string `json:"role"`
}

// Task represents a task item
type Task struct {
    ID        int    `json:"id"`
    Name      string `json:"name"`
    IsDone    bool   `json:"is_done"`
    UserID    int    `json:"user_id"`
}
