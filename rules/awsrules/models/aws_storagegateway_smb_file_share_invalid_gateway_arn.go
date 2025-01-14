// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/issue"
	"github.com/wata727/tflint/tflint"
)

// AwsStoragegatewaySmbFileShareInvalidGatewayArnRule checks the pattern is valid
type AwsStoragegatewaySmbFileShareInvalidGatewayArnRule struct {
	resourceType  string
	attributeName string
	max           int
	min           int
}

// NewAwsStoragegatewaySmbFileShareInvalidGatewayArnRule returns new rule with default attributes
func NewAwsStoragegatewaySmbFileShareInvalidGatewayArnRule() *AwsStoragegatewaySmbFileShareInvalidGatewayArnRule {
	return &AwsStoragegatewaySmbFileShareInvalidGatewayArnRule{
		resourceType:  "aws_storagegateway_smb_file_share",
		attributeName: "gateway_arn",
		max:           500,
		min:           50,
	}
}

// Name returns the rule name
func (r *AwsStoragegatewaySmbFileShareInvalidGatewayArnRule) Name() string {
	return "aws_storagegateway_smb_file_share_invalid_gateway_arn"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsStoragegatewaySmbFileShareInvalidGatewayArnRule) Enabled() bool {
	return true
}

// Type returns the rule severity
func (r *AwsStoragegatewaySmbFileShareInvalidGatewayArnRule) Type() string {
	return issue.ERROR
}

// Link returns the rule reference link
func (r *AwsStoragegatewaySmbFileShareInvalidGatewayArnRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsStoragegatewaySmbFileShareInvalidGatewayArnRule) Check(runner *tflint.Runner) error {
	log.Printf("[INFO] Check `%s` rule for `%s` runner", r.Name(), runner.TFConfigPath())

	return runner.WalkResourceAttributes(r.resourceType, r.attributeName, func(attribute *hcl.Attribute) error {
		var val string
		err := runner.EvaluateExpr(attribute.Expr, &val)

		return runner.EnsureNoError(err, func() error {
			if len(val) > r.max {
				runner.EmitIssue(
					r,
					"gateway_arn must be 500 characters or less",
					attribute.Expr.Range(),
				)
			}
			if len(val) < r.min {
				runner.EmitIssue(
					r,
					"gateway_arn must be 50 characters or higher",
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
