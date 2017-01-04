package jwtauth

import (
  "github.com/Masterminds/squirrel"
)

type pagination struct {
  Page     *uint64
  Per_Page *uint64
}

func (p *pagination) Start() uint64 {
  if p.Page != nil && p.Per_Page != nil {
    page := *p.Page
    perPage := *p.Per_Page
    return (page - 1) * perPage
  }
  return 0
}

func (p *pagination) PageLimit(q squirrel.SelectBuilder) squirrel.SelectBuilder {
	if p != nil && p.Page != nil && p.Per_Page != nil {
    return q.Offset(p.Start()).Limit(*p.Per_Page)
	}
	return q
}

type paginationView struct {
  From  int `json:"from"`
  To    int `json:"to"`
  Total int `json:"total"`
  LastPage int `json:"last_page"`
  CurrentPage int `json:"current_page"`
}

func newPaginationView(p *pagination, dataSize int, total int) paginationView {
  var from int = 1;
  var lastPage int = 0
  var currentPage int = 0
  if p != nil {
    from = int(p.Start()) + 1
    if p.Per_Page != nil && *p.Per_Page > 0 {
      perPage := int(*p.Per_Page)
      lastPage = total / perPage
      if total % perPage > 0 {
        lastPage += 1
      }
      currentPage = from / int(*p.Per_Page) + 1
    }
  }

  return paginationView{
    Total: total,
    From: from,
    To: from + dataSize - 1,
    LastPage: lastPage,
    CurrentPage: currentPage,
  }
}
