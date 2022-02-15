package casbin

import (
	"time"

	"github.com/casbin/casbin/v2"
)

type Enforcer = casbin.Enforcer

type Options struct {
	Model    string        // model config file path
	Debug    bool          // debug mode
	Enable   bool          // enable permission
	AutoLoad bool          // auto load policy
	Duration time.Duration // auto load duration
	DbTable  string        // policy table name
	DbLink   string        // database source url, example: mysql:root:12345678@tcp(127.0.0.1:3306)/test
}

// NewEnforcer create a casbin enforcer.
func NewEnforcer(opt *Options) (enforcer *Enforcer, err error) {
	var adp *adapter

	if adp, err = newAdapter(opt.DbLink, opt.DbTable, opt.Debug); err != nil {
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
