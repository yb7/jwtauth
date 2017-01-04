package jwtauth

import (
	"errors"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
  sq "github.com/Masterminds/squirrel"
  "github.com/Sirupsen/logrus"
)

var securityLog = logrus.WithField("f", "models.Security")

const (
	signingKey             = "e0943jfnndafvoijrgojo@##I*)#(foijaojfgo)"
	accessTokenValidPeriod = 30 //days
  tokenLoginID           = "loginID"
	tokenUsername          = "user"
	tokenRoles             = "roles"
	tokenExpiresAt         = "exp"
	tokenIssueAt           = "iss"
	tokenClient            = "client"
  tokenTimeFormat        = "2006-01-02 15:04:05"
)

func isAccessTokenValid(dbProxy sq.DBProxyBeginner, accessToken *AccessToken) bool {
  log := securityLog.WithField("m", "IsAccessTokenValid")
  log.Debugf("accessToken.ExpiresAt[%s]\n", accessToken.ExpiresAt.Format(tokenTimeFormat))
	if time.Now().After(accessToken.ExpiresAt) {
		return false
	}

  loginVo, err := getLoginRecord(dbProxy, accessToken.LoginID)
  if err != nil {
    log.Error(err.Error())
    return false
  }
  if loginVo.LogoutAt != nil {
    log.Infof("login id[%d] has been logged out at %s", loginVo.ID, loginVo.LogoutAt.Format(tokenTimeFormat))
    return false
  }
  return true
}

// IssueJwtAccessToken func
func issueJwtAccessToken(dbProxy sq.BaseRunner, username string, client string, roles []string) (string, error) {
  log := securityLog.WithField("m", "IssueJwtAccessToken")

  loginVo, err := recordLogin(dbProxy, username, client)
  if err != nil {
    return "", err
  }
	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
    tokenLoginID : loginVo.ID,
		tokenUsername: username,
		tokenRoles: strings.Join(roles, ","),
		tokenExpiresAt: time.Now().Add(time.Hour * 24 * accessTokenValidPeriod).Format(tokenTimeFormat),
		tokenIssueAt: time.Now().Format(tokenTimeFormat),
		tokenClient: client,
	})
  log.Debugf("Issue AccessToken: %v\n", token.Claims)
	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString([]byte(signingKey))
	return tokenString, err
}

func doLogout(dbProxy sq.DBProxyBeginner, accessToken *AccessToken) error {
  log := securityLog.WithField("m", "Logout")
  _, err := sq.Update("login_record").Set("logout_at", time.Now()).Where(sq.Eq{"id": accessToken.LoginID}).RunWith(dbProxy).Exec()
  if err != nil {
    log.Error(err.Error())
  }
  return err
}

//ErrAccessTokenNotValid field
var ErrAccessTokenNotValid = errors.New("access token not valid")
