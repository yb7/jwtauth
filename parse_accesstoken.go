package jwtauth

import (
  "time"
  "github.com/dgrijalva/jwt-go"
  "fmt"
  "strings"
  "errors"
)


// AccessToken struct
type AccessToken struct {
  LoginID   int
  Username  string
  Roles     []string
  ExpiresAt time.Time
  IssueAt   time.Time
  Client    string
}

func parseJwtAccessToken(signedString string) (*AccessToken, error) {
  t, err := jwt.Parse(signedString, func(token *jwt.Token) (interface{}, error) {
    // Always check the signing method
    if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
      return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
    }

    // Return the key for validation
    return []byte(signingKey), nil
  })

  if err != nil {
    return nil, err
  }

  if !t.Valid {
    return nil, ErrAccessTokenNotValid
  }
  if claims, ok := t.Claims.(jwt.MapClaims); ok && t.Valid {
    return claimsToAccessToken(claims)
  } else {
    return nil, errors.New("not type of jwt.MapClaims")
  }

}

func claimsToAccessToken(mapClaims jwt.MapClaims) (token *AccessToken, err error) {
  log := securityLog.WithField("m", "claimsToAccessToken")
  claims := claimType(mapClaims)
  defer func() {
    if r := recover(); r != nil {
      switch x := r.(type) {
      case string:
        err = errors.New(x)
      case error:
        err = x
      default:
        err = errors.New("Unknown panic")
      }
      log.Error(err.Error())
    }
  }()
  token = new(AccessToken)
  token.LoginID = claims.intInClaims(tokenLoginID)
  token.Username = claims.strInClaims(tokenUsername)
  token.Roles = strings.Split(claims.strInClaims(tokenRoles), ",")
  token.ExpiresAt = claims.timeInClaims(tokenExpiresAt)
  token.IssueAt = claims.timeInClaims(tokenIssueAt)
  token.Client = claims.strInClaims(tokenClient)
  return
}

type claimType jwt.MapClaims
func (claims claimType) strInClaims(key string) string {
  if v, ok := claims[key]; ok {
    if str, validType := v.(string); validType {
      return str
    }
    panic(fmt.Sprintf("value of AccessToken[%s] is type of %T, not type of string", v, key))
  }
  panic(fmt.Sprintf("security: missing field [%s] in access token", key))
}
func (claims claimType) timeInClaims(key string) time.Time {
  timeStr := claims.strInClaims(key)
  t, err := time.Parse(tokenTimeFormat, timeStr)
  if err != nil {
    panic(fmt.Sprintf("value of AccessToken[%s] is not apply the format %s", key, tokenTimeFormat))
  }
  return t
}

func (claims claimType) intInClaims(key string) int {
  if v, ok := claims[key]; ok {
    if intValue, validType := v.(float64); validType {
      return int(intValue)
    }
    panic(fmt.Sprintf("value of AccessToken[%s] is type of %T, not type of float64", v, key))
  }
  panic(fmt.Sprintf("missing field [%s] in access token", key))
}
