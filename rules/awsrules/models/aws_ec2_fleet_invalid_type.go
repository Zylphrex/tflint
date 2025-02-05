// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/issue"
	"github.com/wata727/tflint/tflint"
)

// AwsEc2FleetInvalidTypeRule checks the pattern is valid
type AwsEc2FleetInvalidTypeRule struct {
	resourceType  string
	attributeName string
	enum          []string
}

// NewAwsEc2FleetInvalidTypeRule returns new rule with default attributes
func NewAwsEc2FleetInvalidTypeRule() *AwsEc2FleetInvalidTypeRule {
	return &AwsEc2FleetInvalidTypeRule{
		resourceType:  "aws_ec2_fleet",
		attributeName: "type",
		enum: []string{
			"request",
			"maintain",
			"instant",
		},
	}
}

// Name returns the rule name
func (r *AwsEc2FleetInvalidTypeRule) Name() string {
	return "aws_ec2_fleet_invalid_type"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsEc2FleetInvalidTypeRule) Enabled() bool {
	return true
}

// Type returns the rule severity
func (r *AwsEc2FleetInvalidTypeRule) Type() string {
	return issue.ERROR
}

// Link returns the rule reference link
func (r *AwsEc2FleetInvalidTypeRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsEc2FleetInvalidTypeRule) Check(runner *tflint.Runner) error {
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
					`type is not a valid value`,
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
