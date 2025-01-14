// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/issue"
	"github.com/wata727/tflint/tflint"
)

// AwsSpotFleetRequestInvalidFleetTypeRule checks the pattern is valid
type AwsSpotFleetRequestInvalidFleetTypeRule struct {
	resourceType  string
	attributeName string
	enum          []string
}

// NewAwsSpotFleetRequestInvalidFleetTypeRule returns new rule with default attributes
func NewAwsSpotFleetRequestInvalidFleetTypeRule() *AwsSpotFleetRequestInvalidFleetTypeRule {
	return &AwsSpotFleetRequestInvalidFleetTypeRule{
		resourceType:  "aws_spot_fleet_request",
		attributeName: "fleet_type",
		enum: []string{
			"request",
			"maintain",
			"instant",
		},
	}
}

// Name returns the rule name
func (r *AwsSpotFleetRequestInvalidFleetTypeRule) Name() string {
	return "aws_spot_fleet_request_invalid_fleet_type"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsSpotFleetRequestInvalidFleetTypeRule) Enabled() bool {
	return true
}

// Type returns the rule severity
func (r *AwsSpotFleetRequestInvalidFleetTypeRule) Type() string {
	return issue.ERROR
}

// Link returns the rule reference link
func (r *AwsSpotFleetRequestInvalidFleetTypeRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsSpotFleetRequestInvalidFleetTypeRule) Check(runner *tflint.Runner) error {
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
					`fleet_type is not a valid value`,
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
