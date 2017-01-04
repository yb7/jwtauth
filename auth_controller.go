package jwtauth

import (
	//	"fmt"
	"github.com/wangyibin/echoswg"
  "fmt"
)

type (
	loginReq struct {
		Body *loginVo
	}
	loginVo struct {
		Username string
		Password string
		Client   string
	}
  loginSuccessResponse struct {
    AccessToken string     `json:"accessToken"`
    Username    string     `json:"username"`
    Roles       []string   `json:"roles"`
  }
)

var _config Config

func login(req *loginReq) (*loginSuccessResponse, error) {
  tx, err := _config.DBProxyBeginner.Begin()

  if err != nil {
    fmt.Printf(err.Error())
    return nil, err
  }
  defer tx.Rollback()

  roles, err := _config.ValidateUserFunc(req.Body.Username, req.Body.Password)
  if err != nil {
    return nil, err
  }
  accessToken, err := issueJwtAccessToken(tx, req.Body.Username, req.Body.Client, roles)
  if err != nil {
    return nil, err
  }
  tx.Commit()
  return &loginSuccessResponse{AccessToken: accessToken, Username: req.Body.Username, Roles: roles}, nil
}

func logout(accessToken *AccessToken) error {
  return doLogout(_config.DBProxyBeginner, accessToken)
}

func Init(config Config) {
  _config = config
	g := echoswg.NewApiGroup(_config.EchoInstance, "auth", "/api/auth");
	g.SetDescription("认证")
	g.POST("/login", login)
	g.GET("/logout", CheckRole(), logout)
}
