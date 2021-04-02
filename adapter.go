package casbin

import (
	"errors"
	"fmt"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/gogf/gf/database/gdb"
	"runtime"
)

const (
	defaultTableName = "casbin_policy"
)

var (
	ErrMissingDatabaseDriver = errors.New("missing database driver")
	ErrMissingDatabaseSource = errors.New("missing database source")
)

type Adapter struct {
	db             gdb.DB
	TableName      string
	DatabaseDriver string
	DatabaseSource string
}

type Rule struct {
	PType string `json:"ptype"`
	V0    string `json:"v0"`
	V1    string `json:"v1"`
	V2    string `json:"v2"`
	V3    string `json:"v3"`
	V4    string `json:"v4"`
	V5    string `json:"v5"`
}

// Create a casbin adapter
func NewAdapter(a *Adapter) (*Adapter, error) {
	if err := a.init(); err != nil {
		return nil, err
	}

	return a, nil
}

// Init database arguments
func (a *Adapter) init() error {
	if a.DatabaseDriver == "" {
		return ErrMissingDatabaseDriver
	}

	if a.DatabaseSource == "" {
		return ErrMissingDatabaseSource
	}

	if a.TableName == "" {
		a.TableName = defaultTableName
	}

	gdb.SetConfigGroup("casbin", gdb.ConfigGroup{
		gdb.ConfigNode{
			Type:     a.DatabaseDriver,
			LinkInfo: a.DatabaseSource,
			Role:     "master",
			Weight:   100,
		},
	})

	db, err := gdb.New("casbin")

	if err != nil {
		return err
	}

	a.db = db

	if err = a.db.PingMaster(); err != nil {
		return err
	}

	if err = a.createTable(); err != nil {
		return err
	}

	runtime.SetFinalizer(a, func(a *Adapter) {
		a.db = nil
	})

	return nil
}

// Create this policy table
func (a *Adapter) createTable() error {
	sql := `
		CREATE TABLE IF NOT EXISTS %s (
			ptype VARCHAR(10) NOT NULL DEFAULT '' COMMENT '',
			v0 VARCHAR(256) NOT NULL DEFAULT '' COMMENT '',
			v1 VARCHAR(256) NOT NULL DEFAULT '' COMMENT '',
			v2 VARCHAR(256) NOT NULL DEFAULT '' COMMENT '',
			v3 VARCHAR(256) NOT NULL DEFAULT '' COMMENT '',
			v4 VARCHAR(256) NOT NULL DEFAULT '' COMMENT '',
			v5 VARCHAR(256) NOT NULL DEFAULT '' COMMENT ''
		) ENGINE = InnoDB COMMENT = 'policy table';
	`
	_, err := a.db.Exec(fmt.Sprintf(sql, a.TableName))

	return err
}

// Drop the policy table
func (a *Adapter) dropTable() error {
	_, err := a.db.Exec(fmt.Sprintf("DROP TABLE %s", a.TableName))
	return err
}

// Loads all policy rules from the storage.
func (a *Adapter) LoadPolicy(model model.Model) error {
	var rules []Rule

	if err := a.db.Model(a.TableName).Scan(&rules); err != nil {
		return err
	}

	for _, rule := range rules {
		a.loadPolicyRule(rule, model)
	}

	return nil
}

// Saves all policy rules to the storage.
func (a *Adapter) SavePolicy(model model.Model) error {
	var (
		err   error
		rules = make([]Rule, 0)
	)

	if err = a.dropTable(); err != nil {
		return err
	}

	if err = a.createTable(); err != nil {
		return err
	}

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			rules = append(rules, a.buildPolicyRule(ptype, rule))
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			rules = append(rules, a.buildPolicyRule(ptype, rule))
		}
	}

	if count := len(rules); count > 0 {
		_, err = a.db.Model(a.TableName).Data(&rules).Insert()

		if err != nil {
			return err
		}
	}

	return nil
}

// Adds a policy rule to the storage.
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	line := a.buildPolicyRule(ptype, rule)
	_, err := a.db.Model(a.TableName).Data(&line).Insert()
	return err
}

// Removes a policy rule from the storage.
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	return a.deletePolicyRule(a.buildPolicyRule(ptype, rule))
}

// Removes policy rules that match the filter from the storage.
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	rule := Rule{}

	rule.PType = ptype
	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		rule.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		rule.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		rule.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		rule.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		rule.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		rule.V5 = fieldValues[5-fieldIndex]
	}
	err := a.deletePolicyRule(rule)
	return err
}

// Adds a policy rule to the storage.
func (a *Adapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	var lines []Rule
	for _, rule := range rules {
		lines = append(lines, a.buildPolicyRule(ptype, rule))
	}

	_, err := a.db.Model(a.TableName).Data(&lines).Insert()
	return err
}

// Removes a policy rule from the storage.
func (a *Adapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	db := a.db.Model(a.TableName)

	for _, rule := range rules {
		line := a.buildPolicyRule(ptype, rule)
		sql := ""
		val := make([]interface{}, 0)

		sql = "(ptype = ?"
		val = append(val, ptype)
		if line.V0 != "" {
			sql += " and v0 = ?"
			val = append(val, line.V0)
		}
		if line.V1 != "" {
			sql += " and v1 = ?"
			val = append(val, line.V1)
		}
		if line.V2 != "" {
			sql += " and v2 = ?"
			val = append(val, line.V2)
		}
		if line.V3 != "" {
			sql += " and v3 = ?"
			val = append(val, line.V3)
		}
		if line.V4 != "" {
			sql += " and v4 = ?"
			val = append(val, line.V4)
		}
		if line.V5 != "" {
			sql += " and v5 = ?"
			val = append(val, line.V5)
		}
		sql += ")"

		db.Or(sql, val...)
	}

	_, err := db.Delete()
	return err
}

// Updates a policy rule from storage.
func (a *Adapter) UpdatePolicy(sec string, ptype string, oldPolicy, newPolicy []string) error {
	oldRule := a.buildPolicyRule(ptype, oldPolicy)
	newRule := a.buildPolicyRule(ptype, newPolicy)
	_, err := a.db.Model(a.TableName).Update(&oldRule, &newRule)
	return err
}

// Updates some policy rules to storage, like db, redis.
func (a *Adapter) UpdatePolicies(sec string, ptype string, oldPolicies, newPolicies [][]string) error {
	for i, oldPolicy := range oldPolicies {
		oldRule := a.buildPolicyRule(ptype, oldPolicy)
		newRule := a.buildPolicyRule(ptype, newPolicies[i])
		_, err := a.db.Model(a.TableName).Update(&oldRule, &newRule)
		return err
	}

	return nil
}

// Load policy rules
func (a *Adapter) loadPolicyRule(rule Rule, model model.Model) {
	ruleText := rule.PType

	if rule.V0 != "" {
		ruleText += ", " + rule.V0
	}
	if rule.V1 != "" {
		ruleText += ", " + rule.V1
	}
	if rule.V2 != "" {
		ruleText += ", " + rule.V2
	}
	if rule.V3 != "" {
		ruleText += ", " + rule.V3
	}
	if rule.V4 != "" {
		ruleText += ", " + rule.V4
	}
	if rule.V5 != "" {
		ruleText += ", " + rule.V5
	}

	persist.LoadPolicyLine(ruleText, model)
}

// Build policy rules
func (a *Adapter) buildPolicyRule(ptype string, data []string) Rule {
	rule := Rule{}

	rule.PType = ptype

	if len(data) > 0 {
		rule.V0 = data[0]
	}
	if len(data) > 1 {
		rule.V1 = data[1]
	}
	if len(data) > 2 {
		rule.V2 = data[2]
	}
	if len(data) > 3 {
		rule.V3 = data[3]
	}
	if len(data) > 4 {
		rule.V4 = data[4]
	}
	if len(data) > 5 {
		rule.V5 = data[5]
	}

	return rule
}

// Delete policy rules
func (a *Adapter) deletePolicyRule(rule Rule) error {
	db := a.db.Model(a.TableName)

	db.Where("ptype = ?", rule.PType)
	if rule.V0 != "" {
		db.Where("v0 = ?", rule.V0)
	}
	if rule.V1 != "" {
		db.Where("v1 = ?", rule.V1)
	}
	if rule.V2 != "" {
		db.Where("v2 = ?", rule.V2)
	}
	if rule.V3 != "" {
		db.Where("v3 = ?", rule.V3)
	}
	if rule.V4 != "" {
		db.Where("v4 = ?", rule.V4)
	}
	if rule.V5 != "" {
		db.Where("v5 = ?", rule.V5)
	}

	_, err := db.Delete()
	return err
}
