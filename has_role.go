package jwtauth

import (
	"errors"
	"fmt"
	"github.com/labstack/echo"
)

const (
	//Bearer field
	_Bearer = "Bearer"
)

//ErrNoAccessToken field
var ErrNoAccessToken = errors.New("no access token found ")

// CheckRole func
func CheckRole(roles ...string) func(echo.Context) (*AccessToken, error) {
	return func(c echo.Context) (*AccessToken, error) {
		accessToken, err := parseJwt(c)
		if err != nil {
			return nil, err
		}
		if !isAccessTokenValid(_config.DBProxyBeginner, accessToken) {
			return nil, _config.ErrorAccessTokenExpired
		}

		fmt.Printf("roles request: %v, roles in access token: %v\n", roles, accessToken.Roles)
		if len(roles) == 0 || hasCommon(roles, accessToken.Roles) {
			// c.Set("AccessToken", accessToken)
			return accessToken, nil
		}

		return nil, _config.ErrorPermissionDenied
	}
}

func hasCommon(left []string, right []string) bool {
	for _, l := range left {
		for _, r := range right {
			if l == r {
				return true
			}
		}
	}
	return false
}

func parseJwt(c echo.Context) (*AccessToken, error) {
	signedString, err := getAccessToken(c)

	if err != nil {
		return nil, err
	}

	return parseJwtAccessToken(signedString)
}

func getAccessToken(c echo.Context) (string, error) {
	var signedString string
	auth := c.Request().Header().Get("Authorization")
	l := len(_Bearer)

	if len(auth) > l+1 && auth[:l] == _Bearer {
		signedString = auth[l+1:]
	} else if len(c.Request().URL().QueryParam("access_token")) > 1 {
		signedString = c.Request().URL().QueryParam("access_token")
	}
	//else if cookie, err := c.Request().Cookie("access_token"); err == nil {
	//	signedString = cookie.Value
	//}
	if len(signedString) == 0 {
		return "", ErrNoAccessToken
	}
	return signedString, nil
}
