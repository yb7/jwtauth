package jwtauth

import (
  "time"
  sq "github.com/Masterminds/squirrel"
)

type _LoginRecord struct {
  ID       int
  Username string
  Client   string
  LoginAt  time.Time
  LogoutAt *time.Time
}

func recordLogin(db sq.BaseRunner, username string, client string) (*_LoginRecord, error) {
  log := securityLog.WithField("m", "RecordLogin")
  Now := time.Now()
  _, err := sq.Update("login_record").Set("logout_at", Now).Where(sq.Eq{"username": username, "client": client}).
    RunWith(db).Exec()
  if err != nil {
    log.Error(err.Error())
    return nil, err
  }

  res, err := sq.Insert("login_record").Columns("username", "client", "login_at").
    Values(username, client, Now).
    RunWith(db).Exec()
  if err != nil {
    log.Error(err.Error())
    return nil, err
  }
  id64, err := res.LastInsertId()
  if err != nil {
    log.Error(err.Error())
    return nil, err
  }

  return &_LoginRecord{
    ID: int(id64),
    Username: username,
    Client: client,
    LoginAt: Now,
  }, nil
}

func getLoginRecord(conn sq.BaseRunner, id int) (*_LoginRecord, error) {
  query := sq.Select("id, username, client, login_at, logout_at").From("login_record").
    Where("id=?", id).RunWith(conn)
  return sqlRowToLoginRecord(query.QueryRow())
}

func sqlRowToLoginRecord(row sq.RowScanner) (*_LoginRecord, error) {
  log := securityLog.WithField("m", "rowsToLoginRecord")
  var (
    id int
    username string
    client string
    loginAt time.Time
    logoutAt *time.Time
  )
  if err := row.Scan(&id, &username, &client, &loginAt, &logoutAt); err != nil {
    log.Error(err.Error())
    return nil, err
  }
  return &_LoginRecord{ID: id, Username: username, Client: client, LoginAt: loginAt, LogoutAt: logoutAt}, nil

}

func findLoginRecords(conn sq.BaseRunner, pagination *pagination) ([]*_LoginRecord, error) {
  log := securityLog.WithField("m", "findLoginRecords")
  query := sq.Select("id, username, client, login_at, logout_at").From("login_record").OrderBy("login_at desc")
  if pagination != nil {
    query = pagination.PageLimit(query)
  }
  rows, err := query.RunWith(conn).Query()
  if err != nil {
    log.Error(err.Error())
    return nil, err
  }
  var records []*_LoginRecord
  for rows.Next() {
    r, err := sqlRowToLoginRecord(rows)
    if err != nil {
      return nil, err
    }
    records = append(records, r)
  }
  return records, nil
}
func countLoginRecords(conn sq.BaseRunner) (count int, err error) {
  log := securityLog.WithField("m", "countLoginRecords")
  err = sq.Select("count(id)").From("login_record").RunWith(conn).QueryRow().Scan(&count);
  if err != nil {
    log.Error(err.Error())
  }
  return
}
