package repository

import (
	"math/rand"
	"strconv"
	"sync"
)

type MemoryUserRepo struct {
	mu    sync.RWMutex
	users map[string]User
}

func NewMemoryUserRepo() UserRepo {
	return &MemoryUserRepo{
		users: make(map[string]User),
	}
}

func (us *MemoryUserRepo) CreateUser(username, password string) (User, error) {
	us.mu.Lock()
	defer us.mu.Unlock()

	if _, exists := us.users[username]; exists {
		return User{}, ErrUserExists
	}

	salt := generateRandomSalt()
	passwordHash := simpleHash(password)

	user := User{
		Username:     username,
		Salt:         salt,
		PasswordHash: strconv.Itoa(passwordHash),
	}

	us.users[username] = user
	return user, nil
}

func (us *MemoryUserRepo) GetUser(username string) (User, bool) {
	us.mu.RLock()
	defer us.mu.RUnlock()

	user, exists := us.users[username]
	return user, exists
}

func (us *MemoryUserRepo) UserExists(username string) bool {
	us.mu.RLock()
	defer us.mu.RUnlock()

	_, exists := us.users[username]
	return exists
}

// Helper functions remain the same
func simpleHash(password string) int {
	hash := 0
	for i := 0; i < len(password); i++ {
		hash = ((hash << 5) - hash) + int(password[i])
		hash |= 0
	}
	return hash
}

func generateRandomSalt() string {
	return strconv.Itoa(rand.Intn(1000000) + 100000)
}

// Errors
var ErrUserExists = &UserError{Message: "user already exists"}

type UserError struct {
	Message string
}

func (e *UserError) Error() string {
	return e.Message
}
