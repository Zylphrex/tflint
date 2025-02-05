// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/issue"
	"github.com/wata727/tflint/tflint"
)

// AwsAppautoscalingTargetInvalidServiceNamespaceRule checks the pattern is valid
type AwsAppautoscalingTargetInvalidServiceNamespaceRule struct {
	resourceType  string
	attributeName string
	enum          []string
}

// NewAwsAppautoscalingTargetInvalidServiceNamespaceRule returns new rule with default attributes
func NewAwsAppautoscalingTargetInvalidServiceNamespaceRule() *AwsAppautoscalingTargetInvalidServiceNamespaceRule {
	return &AwsAppautoscalingTargetInvalidServiceNamespaceRule{
		resourceType:  "aws_appautoscaling_target",
		attributeName: "service_namespace",
		enum: []string{
			"ecs",
			"elasticmapreduce",
			"ec2",
			"appstream",
			"dynamodb",
			"rds",
			"sagemaker",
			"custom-resource",
		},
	}
}

// Name returns the rule name
func (r *AwsAppautoscalingTargetInvalidServiceNamespaceRule) Name() string {
	return "aws_appautoscaling_target_invalid_service_namespace"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsAppautoscalingTargetInvalidServiceNamespaceRule) Enabled() bool {
	return true
}

// Type returns the rule severity
func (r *AwsAppautoscalingTargetInvalidServiceNamespaceRule) Type() string {
	return issue.ERROR
}

// Link returns the rule reference link
func (r *AwsAppautoscalingTargetInvalidServiceNamespaceRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsAppautoscalingTargetInvalidServiceNamespaceRule) Check(runner *tflint.Runner) error {
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
					`service_namespace is not a valid value`,
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
