package utils

import (
	"fmt"
	gosyslog "log/syslog"

	kitlog "github.com/go-kit/kit/log"
	//"github.com/go-kit/kit/log/level"
	"github.com/go-kit/kit/log/syslog"
	"github.com/xiewen/mysqlcap/query"
)

type SQLLogService struct {
	Logger kitlog.Logger
}

func NewSQLLog() *SQLLogService {
	w, err := gosyslog.New(gosyslog.LOG_DEBUG, "mycap-sql")
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return &SQLLogService{
		syslog.NewSyslogLogger(w, kitlog.NewLogfmtLogger),
	}
}

func (s *SQLLogService) Log(cmd string, txt string) {
	switch cmd {
	case "COM_INIT_DB":
		s.Logger.Log("cmd", cmd, "sql", fmt.Sprintf("USE %s", txt))
	case "COM_DROP_DB":
		s.Logger.Log("cmd", cmd, "sql", fmt.Sprintf("DROP DATABASE %s", txt))
	case "COM_CREATE_DB":
		s.Logger.Log("cmd", cmd, "sql", fmt.Sprintf("CREATE DATABASE %s", txt))
	case "COM_QUERY":
		finesql := query.Fingerprint(txt)
		fineid := query.Id(finesql)
		s.Logger.Log("cmd", cmd, "sql", txt, "finesql", finesql, "fineid", fineid)
	case "COM_STMT_PREPARE":
		s.Logger.Log("cmd", cmd, "sql", txt)
	case "COM_STMT_EXECUTE":
		s.Logger.Log("cmd", cmd, "sql", txt)
	}
}

type ErrLogService struct {
	Logger kitlog.Logger
}

func NewErrLog() *ErrLogService {
	w, err := gosyslog.New(gosyslog.LOG_DEBUG, "mycap-err")
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return &ErrLogService{
		syslog.NewSyslogLogger(w, kitlog.NewLogfmtLogger),
	}
}

func (s *ErrLogService) Log(msg string) {
	s.Logger.Log("msg", msg)
}
