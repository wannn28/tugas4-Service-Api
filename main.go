package main

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	// Koneksi ke database MySQL
	// Ganti username, password, dan dbname sesuai dengan konfigurasi MySQL Anda
	db, err := sql.Open("mysql", "root:@tcp(localhost:3306)/todos")
	if err != nil {
		panic(fmt.Sprintf("Gagal terhubung ke database: %v", err))
	}
	defer db.Close()

	// Uji koneksi database
	if err = db.Ping(); err != nil {
		panic(fmt.Sprintf("Gagal ping database: %v", err))
	}

	// Buat tabel jika belum ada
	// Tabel users
	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(50) NOT NULL
        )`)
	if err != nil {
		panic(fmt.Sprintf("Gagal membuat tabel users: %v", err))
	}

	// Tabel tasks
	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS tasks (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            is_done BOOLEAN NOT NULL,
            user_id INT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )`)
	if err != nil {
		panic(fmt.Sprintf("Gagal membuat tabel tasks: %v", err))
	}

	// Sisipkan pengguna Admin jika belum ada
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
	if err != nil {
		panic(fmt.Sprintf("Gagal hash password: %v", err))
	}

	_, err = db.Exec(`
        INSERT IGNORE INTO users (username, password_hash, role)
        VALUES (?, ?, ?)`,
		"admin", string(hashedPassword), "Admin")
	if err != nil {
		panic(fmt.Sprintf("Gagal menyisipkan pengguna admin: %v", err))
	}

	// Inisialisasi Echo
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Sediakan koneksi DB ke handler
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Set("db", db)
			return next(c)
		}
	})

	// Atur rute
	Route(e)

	// Mulai server
	e.Logger.Fatal(e.Start(":8080"))
}
