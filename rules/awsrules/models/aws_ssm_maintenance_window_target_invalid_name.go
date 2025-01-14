// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"
	"regexp"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/issue"
	"github.com/wata727/tflint/tflint"
)

// AwsSsmMaintenanceWindowTargetInvalidNameRule checks the pattern is valid
type AwsSsmMaintenanceWindowTargetInvalidNameRule struct {
	resourceType  string
	attributeName string
	max           int
	min           int
	pattern       *regexp.Regexp
}

// NewAwsSsmMaintenanceWindowTargetInvalidNameRule returns new rule with default attributes
func NewAwsSsmMaintenanceWindowTargetInvalidNameRule() *AwsSsmMaintenanceWindowTargetInvalidNameRule {
	return &AwsSsmMaintenanceWindowTargetInvalidNameRule{
		resourceType:  "aws_ssm_maintenance_window_target",
		attributeName: "name",
		max:           128,
		min:           3,
		pattern:       regexp.MustCompile(`^[a-zA-Z0-9_\-.]{3,128}$`),
	}
}

// Name returns the rule name
func (r *AwsSsmMaintenanceWindowTargetInvalidNameRule) Name() string {
	return "aws_ssm_maintenance_window_target_invalid_name"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsSsmMaintenanceWindowTargetInvalidNameRule) Enabled() bool {
	return true
}

// Type returns the rule severity
func (r *AwsSsmMaintenanceWindowTargetInvalidNameRule) Type() string {
	return issue.ERROR
}

// Link returns the rule reference link
func (r *AwsSsmMaintenanceWindowTargetInvalidNameRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsSsmMaintenanceWindowTargetInvalidNameRule) Check(runner *tflint.Runner) error {
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
					"name must be 3 characters or higher",
					attribute.Expr.Range(),
				)
			}
			if !r.pattern.MatchString(val) {
				runner.EmitIssue(
					r,
					`name does not match valid pattern ^[a-zA-Z0-9_\-.]{3,128}$`,
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
