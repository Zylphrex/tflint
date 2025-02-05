// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/issue"
	"github.com/wata727/tflint/tflint"
)

// AwsMqBrokerInvalidDeploymentModeRule checks the pattern is valid
type AwsMqBrokerInvalidDeploymentModeRule struct {
	resourceType  string
	attributeName string
	enum          []string
}

// NewAwsMqBrokerInvalidDeploymentModeRule returns new rule with default attributes
func NewAwsMqBrokerInvalidDeploymentModeRule() *AwsMqBrokerInvalidDeploymentModeRule {
	return &AwsMqBrokerInvalidDeploymentModeRule{
		resourceType:  "aws_mq_broker",
		attributeName: "deployment_mode",
		enum: []string{
			"SINGLE_INSTANCE",
			"ACTIVE_STANDBY_MULTI_AZ",
		},
	}
}

// Name returns the rule name
func (r *AwsMqBrokerInvalidDeploymentModeRule) Name() string {
	return "aws_mq_broker_invalid_deployment_mode"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsMqBrokerInvalidDeploymentModeRule) Enabled() bool {
	return true
}

// Type returns the rule severity
func (r *AwsMqBrokerInvalidDeploymentModeRule) Type() string {
	return issue.ERROR
}

// Link returns the rule reference link
func (r *AwsMqBrokerInvalidDeploymentModeRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsMqBrokerInvalidDeploymentModeRule) Check(runner *tflint.Runner) error {
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
					`deployment_mode is not a valid value`,
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
