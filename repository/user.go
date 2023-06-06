package repository

import (
	"a21hc3NpZ25tZW50/model"

	"gorm.io/gorm"
)

type UserRepository interface {
	GetUserByEmail(email string) (model.User, error)
	CreateUser(user model.User) (model.User, error)
	GetUserTaskCategory() ([]model.UserTaskCategory, error)
}

type userRepository struct {
	db *gorm.DB
}

func NewUserRepo(db *gorm.DB) *userRepository {
	return &userRepository{db}
}

func (r *userRepository) GetUserByEmail(email string) (model.User, error) {
	var user model.User
	err := r.db.Where("email = ?", email).First(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return model.User{}, nil // Mengembalikan model.User kosong jika pengguna tidak ditemukan
		}
		return model.User{}, err // Mengembalikan error jika terjadi kesalahan lain
	}
	return user, nil // TODO: replace this
}

func (r *userRepository) CreateUser(user model.User) (model.User, error) {
	err := r.db.Create(&user).Error
	if err != nil {
		return user, err
	}
	return user, nil
}

func (r *userRepository) GetUserTaskCategory() ([]model.UserTaskCategory, error) {
	var categories []model.UserTaskCategory
	err := r.db.Table("users").
	Select("users.id, users.fullname AS fullname, users.email AS email, tasks.title AS task, tasks.deadline AS deadline, tasks.priority AS priority, tasks.status AS status, categories.name AS category").
	Joins("JOIN tasks ON tasks.user_id = users.id").
	Joins("JOIN categories ON categories.id = tasks.category_id").
	Scan(&categories).Error
	if err != nil {
		return nil, err
	}
	return categories, nil // TODO: replace this
}
