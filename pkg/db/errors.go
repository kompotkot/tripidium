package db

import "errors"

var (
	ErrUserAlreadyExists     = errors.New("user already exists")
	ErrUnexpectedEmptyReturn = errors.New("unexpected empty insert return")
	ErrUserNotFound          = errors.New("user not found")
	ErrTokenNotFound         = errors.New("token not found")
)
