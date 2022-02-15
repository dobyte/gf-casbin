package main

import (
	"fmt"
	"log"

	"github.com/dobyte/gf-casbin"
)

var enforcer *casbin.Enforcer

func init() {
	e, err := casbin.NewEnforcer(&casbin.Options{
		Model:    "./example/model.conf",
		Debug:    true,
		Enable:   true,
		AutoLoad: true,
		DbTable:  "casbin_policy_test",
		DbLink:   "mysql:root:123456@tcp(127.0.0.1:3306)/topic1",
	})

	if err != nil {
		log.Fatalf("Casbin init failure:%s \n", err.Error())
	}

	enforcer = e
}

func main() {
	var (
		ok       bool
		policies [][]string
	)

	// add a permission node for role
	_, _ = enforcer.AddPolicy("role_1", "node_1")

	// batch add permission nodes for roles
	_, _ = enforcer.AddPolicies([][]string{
		{"role_2", "node_2"},
		{"role_3", "node_3"},
	})

	// add a role for user
	_, _ = enforcer.AddGroupingPolicy("user_1", "role_1")

	// batch add roles for users
	_, _ = enforcer.AddGroupingPolicies([][]string{
		{"user_2", "role_2"},
		{"user_3", "role_3"},
	})

	// check role_1 policy
	if ok = enforcer.HasPolicy("role_1", "node_1"); ok {
		fmt.Println("role_1 is allowed access node_1")
	} else {
		fmt.Println("role_1 is not allowed access node_1")
	}

	// check role_1 policy
	if ok = enforcer.HasPolicy("role_1", "node_2"); ok {
		fmt.Println("role_1 is allowed access node_2")
	} else {
		fmt.Println("role_1 is not allowed access node_2")
	}

	// check user_1 policy
	if ok = enforcer.HasGroupingPolicy("user_1", "role_1"); ok {
		fmt.Println("user_1 has role_1")
	} else {
		fmt.Println("user_1 has not role_1")
	}

	// check user_1 policy
	if ok = enforcer.HasGroupingPolicy("user_1", "role_2"); ok {
		fmt.Println("user_1 has role_2")
	} else {
		fmt.Println("user_1 has not role_2")
	}

	// check access permission of user_1
	if ok, _ = enforcer.Enforce("user_1", "node_1"); ok {
		fmt.Println("user_1 is allowed access node_1")
	} else {
		fmt.Println("user_1 is not allowed access node_1")
	}

	// check access permission of user_1
	if ok, _ = enforcer.Enforce("user_1", "node_2"); ok {
		fmt.Println("user_1 is allowed access node_2")
	} else {
		fmt.Println("user_1 is not allowed access node_2")
	}

	// remove a policy
	_, _ = enforcer.RemovePolicy("role_1", "node_1")

	// get all policies
	policies = enforcer.GetPolicy()
	fmt.Println()
	fmt.Println("all policies:")
	fmt.Println(policies)

	// batch remove policies
	_, _ = enforcer.RemovePolicies([][]string{
		{"role_2", "node_2"},
		{"role_3", "node_3"},
	})

	// get all policies
	policies = enforcer.GetPolicy()
	fmt.Println()
	fmt.Println("all policies:")
	fmt.Println(policies)

	// remove a grouping policy
	_, _ = enforcer.RemoveGroupingPolicy("user_1", "role_1")

	// get all grouping policies
	policies = enforcer.GetGroupingPolicy()
	fmt.Println()
	fmt.Println("all grouping policies:")
	fmt.Println(policies)

	// batch remove grouping policies
	_, _ = enforcer.RemoveGroupingPolicies([][]string{
		{"user_2", "role_2"},
		{"user_3", "role_3"},
	})

	// get all grouping policies
	policies = enforcer.GetGroupingPolicy()
	fmt.Println()
	fmt.Println("all grouping policies:")
	fmt.Println(policies)
	fmt.Println()

	// check role_1 policy
	if ok = enforcer.HasPolicy("role_1", "node_1"); ok {
		fmt.Println("role_1 is allowed access node_1")
	} else {
		fmt.Println("role_1 is not allowed access node_1")
	}

	// check role_1 policy
	if ok = enforcer.HasPolicy("role_1", "node_2"); ok {
		fmt.Println("role_1 is allowed access node_2")
	} else {
		fmt.Println("role_1 is not allowed access node_2")
	}

	// check user_1 policy
	if ok = enforcer.HasGroupingPolicy("user_1", "role_1"); ok {
		fmt.Println("user_1 has role_1")
	} else {
		fmt.Println("user_1 has not role_1")
	}

	// check user_1 policy
	if ok = enforcer.HasGroupingPolicy("user_1", "role_2"); ok {
		fmt.Println("user_1 has role_2")
	} else {
		fmt.Println("user_1 has not role_2")
	}
}
