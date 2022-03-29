package casbin

import (
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/gogf/gf/v2/database/gdb"
)

type (
	Enforcer = casbin.Enforcer

	Options struct {
		Model    string        // model config file path
		Debug    bool          // debug mode
		Enable   bool          // enable permission
		AutoLoad bool          // auto load policy
		Duration time.Duration // auto load duration
		DB       gdb.DB        // database instance, Choose between DB and Link parameters. If DB exists, use DB first.
		Link     string        // database source url, Choose between DB and Link parameters. If the DB parameter does not exist, create a DB instance with the Link parameter. example: mysql:root:12345678@tcp(127.0.0.1:3306)/test
		Table    string        // database policy table name
	}
)

// NewEnforcer create a casbin enforcer.
func NewEnforcer(opt *Options) (enforcer *Enforcer, err error) {
	var adp *adapter

	if adp, err = newAdapter(opt.DB, opt.Link, opt.Table); err != nil {
		return
	}

	if enforcer, err = casbin.NewEnforcer(opt.Model, adp); err != nil {
		return
	}

	enforcer.EnableLog(opt.Debug)
	enforcer.EnableEnforce(opt.Enable)
	enforcer.EnableAutoNotifyWatcher(opt.AutoLoad)
	enforcer.EnableAutoSave(true)

	return
}
