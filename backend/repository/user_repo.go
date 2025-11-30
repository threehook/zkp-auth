package repository

type UserRepo interface {
	CreateUser(username, password string) (User, error)
	GetUser(username string) (User, bool)
	UserExists(username string) bool
}

type User struct {
	Username     string `json:"username"`
	Salt         string `json:"salt"`
	PasswordHash string `json:"passwordHash"`
}
