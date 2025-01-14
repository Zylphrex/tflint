// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/issue"
	"github.com/wata727/tflint/tflint"
)

// AwsEc2FleetInvalidExcessCapacityTerminationPolicyRule checks the pattern is valid
type AwsEc2FleetInvalidExcessCapacityTerminationPolicyRule struct {
	resourceType  string
	attributeName string
	enum          []string
}

// NewAwsEc2FleetInvalidExcessCapacityTerminationPolicyRule returns new rule with default attributes
func NewAwsEc2FleetInvalidExcessCapacityTerminationPolicyRule() *AwsEc2FleetInvalidExcessCapacityTerminationPolicyRule {
	return &AwsEc2FleetInvalidExcessCapacityTerminationPolicyRule{
		resourceType:  "aws_ec2_fleet",
		attributeName: "excess_capacity_termination_policy",
		enum: []string{
			"no-termination",
			"termination",
		},
	}
}

// Name returns the rule name
func (r *AwsEc2FleetInvalidExcessCapacityTerminationPolicyRule) Name() string {
	return "aws_ec2_fleet_invalid_excess_capacity_termination_policy"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsEc2FleetInvalidExcessCapacityTerminationPolicyRule) Enabled() bool {
	return true
}

// Type returns the rule severity
func (r *AwsEc2FleetInvalidExcessCapacityTerminationPolicyRule) Type() string {
	return issue.ERROR
}

// Link returns the rule reference link
func (r *AwsEc2FleetInvalidExcessCapacityTerminationPolicyRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsEc2FleetInvalidExcessCapacityTerminationPolicyRule) Check(runner *tflint.Runner) error {
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
					`excess_capacity_termination_policy is not a valid value`,
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
