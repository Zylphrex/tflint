// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/issue"
	"github.com/wata727/tflint/tflint"
)

// AwsLbInvalidLoadBalancerTypeRule checks the pattern is valid
type AwsLbInvalidLoadBalancerTypeRule struct {
	resourceType  string
	attributeName string
	enum          []string
}

// NewAwsLbInvalidLoadBalancerTypeRule returns new rule with default attributes
func NewAwsLbInvalidLoadBalancerTypeRule() *AwsLbInvalidLoadBalancerTypeRule {
	return &AwsLbInvalidLoadBalancerTypeRule{
		resourceType:  "aws_lb",
		attributeName: "load_balancer_type",
		enum: []string{
			"application",
			"network",
		},
	}
}

// Name returns the rule name
func (r *AwsLbInvalidLoadBalancerTypeRule) Name() string {
	return "aws_lb_invalid_load_balancer_type"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsLbInvalidLoadBalancerTypeRule) Enabled() bool {
	return true
}

// Type returns the rule severity
func (r *AwsLbInvalidLoadBalancerTypeRule) Type() string {
	return issue.ERROR
}

// Link returns the rule reference link
func (r *AwsLbInvalidLoadBalancerTypeRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsLbInvalidLoadBalancerTypeRule) Check(runner *tflint.Runner) error {
	log.Printf("[INFO] Check `%s` rule for `%s` runner", r.Name(), runner.TFConfigPath())

	return runner.WalkResourceAttributes(r.resourceType, r.attributeName, func(attribute *hcl.Attribute) error {
		var val string
		err := runner.EvaluateExpr(attribute.Expr, &val)

		return runner.EnsureNoError(err, func() error {
			found := false
			for _, item := range r.enum {
				if item == val {
					found = true
				}
			}
			if !found {
				runner.EmitIssue(
					r,
					`load_balancer_type is not a valid value`,
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
