// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"
	"regexp"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/issue"
	"github.com/wata727/tflint/tflint"
)

// AwsConfigAggregateAuthorizationInvalidAccountIDRule checks the pattern is valid
type AwsConfigAggregateAuthorizationInvalidAccountIDRule struct {
	resourceType  string
	attributeName string
	pattern       *regexp.Regexp
}

// NewAwsConfigAggregateAuthorizationInvalidAccountIDRule returns new rule with default attributes
func NewAwsConfigAggregateAuthorizationInvalidAccountIDRule() *AwsConfigAggregateAuthorizationInvalidAccountIDRule {
	return &AwsConfigAggregateAuthorizationInvalidAccountIDRule{
		resourceType:  "aws_config_aggregate_authorization",
		attributeName: "account_id",
		pattern:       regexp.MustCompile(`^\d{12}$`),
	}
}

// Name returns the rule name
func (r *AwsConfigAggregateAuthorizationInvalidAccountIDRule) Name() string {
	return "aws_config_aggregate_authorization_invalid_account_id"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsConfigAggregateAuthorizationInvalidAccountIDRule) Enabled() bool {
	return true
}

// Type returns the rule severity
func (r *AwsConfigAggregateAuthorizationInvalidAccountIDRule) Type() string {
	return issue.ERROR
}

// Link returns the rule reference link
func (r *AwsConfigAggregateAuthorizationInvalidAccountIDRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsConfigAggregateAuthorizationInvalidAccountIDRule) Check(runner *tflint.Runner) error {
	log.Printf("[INFO] Check `%s` rule for `%s` runner", r.Name(), runner.TFConfigPath())

	return runner.WalkResourceAttributes(r.resourceType, r.attributeName, func(attribute *hcl.Attribute) error {
		var val string
		err := runner.EvaluateExpr(attribute.Expr, &val)

		return runner.EnsureNoError(err, func() error {
			if !r.pattern.MatchString(val) {
				runner.EmitIssue(
					r,
					`account_id does not match valid pattern ^\d{12}$`,
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
