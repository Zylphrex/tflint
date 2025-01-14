// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/issue"
	"github.com/wata727/tflint/tflint"
)

// AwsCloudwatchLogGroupInvalidKmsKeyIDRule checks the pattern is valid
type AwsCloudwatchLogGroupInvalidKmsKeyIDRule struct {
	resourceType  string
	attributeName string
	max           int
}

// NewAwsCloudwatchLogGroupInvalidKmsKeyIDRule returns new rule with default attributes
func NewAwsCloudwatchLogGroupInvalidKmsKeyIDRule() *AwsCloudwatchLogGroupInvalidKmsKeyIDRule {
	return &AwsCloudwatchLogGroupInvalidKmsKeyIDRule{
		resourceType:  "aws_cloudwatch_log_group",
		attributeName: "kms_key_id",
		max:           256,
	}
}

// Name returns the rule name
func (r *AwsCloudwatchLogGroupInvalidKmsKeyIDRule) Name() string {
	return "aws_cloudwatch_log_group_invalid_kms_key_id"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsCloudwatchLogGroupInvalidKmsKeyIDRule) Enabled() bool {
	return true
}

// Type returns the rule severity
func (r *AwsCloudwatchLogGroupInvalidKmsKeyIDRule) Type() string {
	return issue.ERROR
}

// Link returns the rule reference link
func (r *AwsCloudwatchLogGroupInvalidKmsKeyIDRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsCloudwatchLogGroupInvalidKmsKeyIDRule) Check(runner *tflint.Runner) error {
	log.Printf("[INFO] Check `%s` rule for `%s` runner", r.Name(), runner.TFConfigPath())

	return runner.WalkResourceAttributes(r.resourceType, r.attributeName, func(attribute *hcl.Attribute) error {
		var val string
		err := runner.EvaluateExpr(attribute.Expr, &val)

		return runner.EnsureNoError(err, func() error {
			if len(val) > r.max {
				runner.EmitIssue(
					r,
					"kms_key_id must be 256 characters or less",
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
