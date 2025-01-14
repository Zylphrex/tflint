// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/issue"
	"github.com/wata727/tflint/tflint"
)

// AwsRoute53ZoneAssociationInvalidVpcIDRule checks the pattern is valid
type AwsRoute53ZoneAssociationInvalidVpcIDRule struct {
	resourceType  string
	attributeName string
	max           int
}

// NewAwsRoute53ZoneAssociationInvalidVpcIDRule returns new rule with default attributes
func NewAwsRoute53ZoneAssociationInvalidVpcIDRule() *AwsRoute53ZoneAssociationInvalidVpcIDRule {
	return &AwsRoute53ZoneAssociationInvalidVpcIDRule{
		resourceType:  "aws_route53_zone_association",
		attributeName: "vpc_id",
		max:           1024,
	}
}

// Name returns the rule name
func (r *AwsRoute53ZoneAssociationInvalidVpcIDRule) Name() string {
	return "aws_route53_zone_association_invalid_vpc_id"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsRoute53ZoneAssociationInvalidVpcIDRule) Enabled() bool {
	return true
}

// Type returns the rule severity
func (r *AwsRoute53ZoneAssociationInvalidVpcIDRule) Type() string {
	return issue.ERROR
}

// Link returns the rule reference link
func (r *AwsRoute53ZoneAssociationInvalidVpcIDRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsRoute53ZoneAssociationInvalidVpcIDRule) Check(runner *tflint.Runner) error {
	log.Printf("[INFO] Check `%s` rule for `%s` runner", r.Name(), runner.TFConfigPath())

	return runner.WalkResourceAttributes(r.resourceType, r.attributeName, func(attribute *hcl.Attribute) error {
		var val string
		err := runner.EvaluateExpr(attribute.Expr, &val)

		return runner.EnsureNoError(err, func() error {
			if len(val) > r.max {
				runner.EmitIssue(
					r,
					"vpc_id must be 1024 characters or less",
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
