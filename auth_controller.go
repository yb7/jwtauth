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
  loginRecordVo struct {
    ID       int        `json:"id"`
    Username string     `json:"username"`
    Client   string     `json:"client"`
    LoginAt  string     `json:"loginAt"`
    LogoutAt string     `json:"logoutAt"`
  }
  loginRecordPaginationView struct {
    Data       []*loginRecordVo `json:"data"`
    Pagination paginationView   `json:"pagination"`
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

func listLoginRecords(req *struct {
  Page     *uint64
  Per_Page *uint64
}) (*loginRecordPaginationView, error) {
  paginationVo := &pagination{
    Page: req.Page,
    Per_Page: req.Per_Page,
  }
  records, err := findLoginRecords(_config.DBProxyBeginner, paginationVo)
  if err != nil {
    return nil, err
  }
  var vos []*loginRecordVo
  for _, r := range records {
    logoutAt := ""
    if r.LogoutAt != nil {
      logoutAt = (*r.LogoutAt).Format(tokenTimeFormat)
    }
    vos = append(vos, &loginRecordVo{
      ID: r.ID,
      Username: r.Username,
      Client: r.Client,
      LoginAt: r.LoginAt.Format(tokenTimeFormat),
      LogoutAt: logoutAt,
    })
  }
  total, err := countLoginRecords(_config.DBProxyBeginner)
  if err != nil {
    return nil, err
  }
  return &loginRecordPaginationView {
    Data: vos,
    Pagination: newPaginationView(paginationVo, len(vos), total),
  }, nil
}

func Init(config Config) {
  _config = config
	g := echoswg.NewApiGroup(_config.EchoInstance, "auth", "/api/auth");
	g.SetDescription("认证")
	g.POST("/login", login)
	g.GET("/logout", CheckRole(), logout)
  g.GET("/login-records", CheckRole(), listLoginRecords)
}
