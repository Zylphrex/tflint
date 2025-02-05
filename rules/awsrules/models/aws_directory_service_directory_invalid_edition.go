// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/issue"
	"github.com/wata727/tflint/tflint"
)

// AwsDirectoryServiceDirectoryInvalidEditionRule checks the pattern is valid
type AwsDirectoryServiceDirectoryInvalidEditionRule struct {
	resourceType  string
	attributeName string
	enum          []string
}

// NewAwsDirectoryServiceDirectoryInvalidEditionRule returns new rule with default attributes
func NewAwsDirectoryServiceDirectoryInvalidEditionRule() *AwsDirectoryServiceDirectoryInvalidEditionRule {
	return &AwsDirectoryServiceDirectoryInvalidEditionRule{
		resourceType:  "aws_directory_service_directory",
		attributeName: "edition",
		enum: []string{
			"Enterprise",
			"Standard",
		},
	}
}

// Name returns the rule name
func (r *AwsDirectoryServiceDirectoryInvalidEditionRule) Name() string {
	return "aws_directory_service_directory_invalid_edition"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsDirectoryServiceDirectoryInvalidEditionRule) Enabled() bool {
	return true
}

// Type returns the rule severity
func (r *AwsDirectoryServiceDirectoryInvalidEditionRule) Type() string {
	return issue.ERROR
}

// Link returns the rule reference link
func (r *AwsDirectoryServiceDirectoryInvalidEditionRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsDirectoryServiceDirectoryInvalidEditionRule) Check(runner *tflint.Runner) error {
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
					`edition is not a valid value`,
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
