package casbin

import (
	"github.com/casbin/casbin/v2"
	"time"
)

type Enforcer = casbin.Enforcer

type Casbin struct {
	Model          string        // model config file path
	Debug          bool          // debug mode
	Enable         bool          // enable permission
	AutoLoad       bool          // auto load policy
	Duration       time.Duration // auto load duration
	TableName      string        // policy table name
	DatabaseDriver string        // database driver,support MySQL, SQLite, PostgreSQL, Oracle, SQL Server
	DatabaseSource string        // database source url
}

// Create a casbin enforcer
func NewEnforcer(c *Casbin) (*Enforcer, error) {
	var (
		err      error
		adapter  *Adapter
		enforcer *Enforcer
	)

	adapter, err = NewAdapter(&Adapter{
		TableName:      c.TableName,
		DatabaseDriver: c.DatabaseDriver,
		DatabaseSource: c.DatabaseSource,
	})

	if err != nil {
		return nil, err
	}

	enforcer, err = casbin.NewEnforcer(c.Model, adapter)

	if err != nil {
		return nil, err
	}

	enforcer.EnableLog(c.Debug)
	enforcer.EnableEnforce(c.Enable)
	enforcer.EnableAutoNotifyWatcher(c.AutoLoad)

	return enforcer, nil
}
