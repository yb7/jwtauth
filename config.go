package jwtauth

import (
  "github.com/Masterminds/squirrel"
  "github.com/labstack/echo"
)

type Config struct {
  DBProxyBeginner squirrel.DBProxyBeginner
  ValidateUserFunc func(username string, password string) ([]string, error)
  EchoInstance *echo.Echo
  ErrorAccessTokenExpired error
  ErrorPermissionDenied error
}
