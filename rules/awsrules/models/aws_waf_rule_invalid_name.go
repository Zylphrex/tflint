// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/issue"
	"github.com/wata727/tflint/tflint"
)

// AwsWafRuleInvalidNameRule checks the pattern is valid
type AwsWafRuleInvalidNameRule struct {
	resourceType  string
	attributeName string
	max           int
	min           int
}

// NewAwsWafRuleInvalidNameRule returns new rule with default attributes
func NewAwsWafRuleInvalidNameRule() *AwsWafRuleInvalidNameRule {
	return &AwsWafRuleInvalidNameRule{
		resourceType:  "aws_waf_rule",
		attributeName: "name",
		max:           128,
		min:           1,
	}
}

// Name returns the rule name
func (r *AwsWafRuleInvalidNameRule) Name() string {
	return "aws_waf_rule_invalid_name"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsWafRuleInvalidNameRule) Enabled() bool {
	return true
}

// Type returns the rule severity
func (r *AwsWafRuleInvalidNameRule) Type() string {
	return issue.ERROR
}

// Link returns the rule reference link
func (r *AwsWafRuleInvalidNameRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsWafRuleInvalidNameRule) Check(runner *tflint.Runner) error {
	log.Printf("[INFO] Check `%s` rule for `%s` runner", r.Name(), runner.TFConfigPath())

	return runner.WalkResourceAttributes(r.resourceType, r.attributeName, func(attribute *hcl.Attribute) error {
		var val string
		err := runner.EvaluateExpr(attribute.Expr, &val)

		return runner.EnsureNoError(err, func() error {
			if len(val) > r.max {
				runner.EmitIssue(
					r,
					"name must be 128 characters or less",
					attribute.Expr.Range(),
				)
			}
			if len(val) < r.min {
				runner.EmitIssue(
					r,
					"name must be 1 characters or higher",
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
