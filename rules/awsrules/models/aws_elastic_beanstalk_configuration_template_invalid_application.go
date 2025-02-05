// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/issue"
	"github.com/wata727/tflint/tflint"
)

// AwsElasticBeanstalkConfigurationTemplateInvalidApplicationRule checks the pattern is valid
type AwsElasticBeanstalkConfigurationTemplateInvalidApplicationRule struct {
	resourceType  string
	attributeName string
	max           int
	min           int
}

// NewAwsElasticBeanstalkConfigurationTemplateInvalidApplicationRule returns new rule with default attributes
func NewAwsElasticBeanstalkConfigurationTemplateInvalidApplicationRule() *AwsElasticBeanstalkConfigurationTemplateInvalidApplicationRule {
	return &AwsElasticBeanstalkConfigurationTemplateInvalidApplicationRule{
		resourceType:  "aws_elastic_beanstalk_configuration_template",
		attributeName: "application",
		max:           100,
		min:           1,
	}
}

// Name returns the rule name
func (r *AwsElasticBeanstalkConfigurationTemplateInvalidApplicationRule) Name() string {
	return "aws_elastic_beanstalk_configuration_template_invalid_application"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsElasticBeanstalkConfigurationTemplateInvalidApplicationRule) Enabled() bool {
	return true
}

// Type returns the rule severity
func (r *AwsElasticBeanstalkConfigurationTemplateInvalidApplicationRule) Type() string {
	return issue.ERROR
}

// Link returns the rule reference link
func (r *AwsElasticBeanstalkConfigurationTemplateInvalidApplicationRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsElasticBeanstalkConfigurationTemplateInvalidApplicationRule) Check(runner *tflint.Runner) error {
	log.Printf("[INFO] Check `%s` rule for `%s` runner", r.Name(), runner.TFConfigPath())

	return runner.WalkResourceAttributes(r.resourceType, r.attributeName, func(attribute *hcl.Attribute) error {
		var val string
		err := runner.EvaluateExpr(attribute.Expr, &val)

		return runner.EnsureNoError(err, func() error {
			if len(val) > r.max {
				runner.EmitIssue(
					r,
					"application must be 100 characters or less",
					attribute.Expr.Range(),
				)
			}
			if len(val) < r.min {
				runner.EmitIssue(
					r,
					"application must be 1 characters or higher",
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
