// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/issue"
	"github.com/wata727/tflint/tflint"
)

// AwsXraySamplingRuleInvalidHostRule checks the pattern is valid
type AwsXraySamplingRuleInvalidHostRule struct {
	resourceType  string
	attributeName string
	max           int
}

// NewAwsXraySamplingRuleInvalidHostRule returns new rule with default attributes
func NewAwsXraySamplingRuleInvalidHostRule() *AwsXraySamplingRuleInvalidHostRule {
	return &AwsXraySamplingRuleInvalidHostRule{
		resourceType:  "aws_xray_sampling_rule",
		attributeName: "host",
		max:           64,
	}
}

// Name returns the rule name
func (r *AwsXraySamplingRuleInvalidHostRule) Name() string {
	return "aws_xray_sampling_rule_invalid_host"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsXraySamplingRuleInvalidHostRule) Enabled() bool {
	return true
}

// Type returns the rule severity
func (r *AwsXraySamplingRuleInvalidHostRule) Type() string {
	return issue.ERROR
}

// Link returns the rule reference link
func (r *AwsXraySamplingRuleInvalidHostRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsXraySamplingRuleInvalidHostRule) Check(runner *tflint.Runner) error {
	log.Printf("[INFO] Check `%s` rule for `%s` runner", r.Name(), runner.TFConfigPath())

	return runner.WalkResourceAttributes(r.resourceType, r.attributeName, func(attribute *hcl.Attribute) error {
		var val string
		err := runner.EvaluateExpr(attribute.Expr, &val)

		return runner.EnsureNoError(err, func() error {
			if len(val) > r.max {
				runner.EmitIssue(
					r,
					"host must be 64 characters or less",
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
