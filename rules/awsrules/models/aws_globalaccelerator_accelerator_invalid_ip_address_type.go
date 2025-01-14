// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/issue"
	"github.com/wata727/tflint/tflint"
)

// AwsGlobalacceleratorAcceleratorInvalidIPAddressTypeRule checks the pattern is valid
type AwsGlobalacceleratorAcceleratorInvalidIPAddressTypeRule struct {
	resourceType  string
	attributeName string
	enum          []string
}

// NewAwsGlobalacceleratorAcceleratorInvalidIPAddressTypeRule returns new rule with default attributes
func NewAwsGlobalacceleratorAcceleratorInvalidIPAddressTypeRule() *AwsGlobalacceleratorAcceleratorInvalidIPAddressTypeRule {
	return &AwsGlobalacceleratorAcceleratorInvalidIPAddressTypeRule{
		resourceType:  "aws_globalaccelerator_accelerator",
		attributeName: "ip_address_type",
		enum: []string{
			"IPV4",
		},
	}
}

// Name returns the rule name
func (r *AwsGlobalacceleratorAcceleratorInvalidIPAddressTypeRule) Name() string {
	return "aws_globalaccelerator_accelerator_invalid_ip_address_type"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsGlobalacceleratorAcceleratorInvalidIPAddressTypeRule) Enabled() bool {
	return true
}

// Type returns the rule severity
func (r *AwsGlobalacceleratorAcceleratorInvalidIPAddressTypeRule) Type() string {
	return issue.ERROR
}

// Link returns the rule reference link
func (r *AwsGlobalacceleratorAcceleratorInvalidIPAddressTypeRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsGlobalacceleratorAcceleratorInvalidIPAddressTypeRule) Check(runner *tflint.Runner) error {
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
					`ip_address_type is not a valid value`,
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
