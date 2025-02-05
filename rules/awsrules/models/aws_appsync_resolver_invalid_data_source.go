// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"
	"regexp"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/issue"
	"github.com/wata727/tflint/tflint"
)

// AwsAppsyncResolverInvalidDataSourceRule checks the pattern is valid
type AwsAppsyncResolverInvalidDataSourceRule struct {
	resourceType  string
	attributeName string
	pattern       *regexp.Regexp
}

// NewAwsAppsyncResolverInvalidDataSourceRule returns new rule with default attributes
func NewAwsAppsyncResolverInvalidDataSourceRule() *AwsAppsyncResolverInvalidDataSourceRule {
	return &AwsAppsyncResolverInvalidDataSourceRule{
		resourceType:  "aws_appsync_resolver",
		attributeName: "data_source",
		pattern:       regexp.MustCompile(`^[_A-Za-z][_0-9A-Za-z]*$`),
	}
}

// Name returns the rule name
func (r *AwsAppsyncResolverInvalidDataSourceRule) Name() string {
	return "aws_appsync_resolver_invalid_data_source"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsAppsyncResolverInvalidDataSourceRule) Enabled() bool {
	return true
}

// Type returns the rule severity
func (r *AwsAppsyncResolverInvalidDataSourceRule) Type() string {
	return issue.ERROR
}

// Link returns the rule reference link
func (r *AwsAppsyncResolverInvalidDataSourceRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsAppsyncResolverInvalidDataSourceRule) Check(runner *tflint.Runner) error {
	log.Printf("[INFO] Check `%s` rule for `%s` runner", r.Name(), runner.TFConfigPath())

	return runner.WalkResourceAttributes(r.resourceType, r.attributeName, func(attribute *hcl.Attribute) error {
		var val string
		err := runner.EvaluateExpr(attribute.Expr, &val)

		return runner.EnsureNoError(err, func() error {
			if !r.pattern.MatchString(val) {
				runner.EmitIssue(
					r,
					`data_source does not match valid pattern ^[_A-Za-z][_0-9A-Za-z]*$`,
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
