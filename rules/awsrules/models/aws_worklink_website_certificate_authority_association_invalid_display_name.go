// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/issue"
	"github.com/wata727/tflint/tflint"
)

// AwsWorklinkWebsiteCertificateAuthorityAssociationInvalidDisplayNameRule checks the pattern is valid
type AwsWorklinkWebsiteCertificateAuthorityAssociationInvalidDisplayNameRule struct {
	resourceType  string
	attributeName string
	max           int
}

// NewAwsWorklinkWebsiteCertificateAuthorityAssociationInvalidDisplayNameRule returns new rule with default attributes
func NewAwsWorklinkWebsiteCertificateAuthorityAssociationInvalidDisplayNameRule() *AwsWorklinkWebsiteCertificateAuthorityAssociationInvalidDisplayNameRule {
	return &AwsWorklinkWebsiteCertificateAuthorityAssociationInvalidDisplayNameRule{
		resourceType:  "aws_worklink_website_certificate_authority_association",
		attributeName: "display_name",
		max:           100,
	}
}

// Name returns the rule name
func (r *AwsWorklinkWebsiteCertificateAuthorityAssociationInvalidDisplayNameRule) Name() string {
	return "aws_worklink_website_certificate_authority_association_invalid_display_name"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsWorklinkWebsiteCertificateAuthorityAssociationInvalidDisplayNameRule) Enabled() bool {
	return true
}

// Type returns the rule severity
func (r *AwsWorklinkWebsiteCertificateAuthorityAssociationInvalidDisplayNameRule) Type() string {
	return issue.ERROR
}

// Link returns the rule reference link
func (r *AwsWorklinkWebsiteCertificateAuthorityAssociationInvalidDisplayNameRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsWorklinkWebsiteCertificateAuthorityAssociationInvalidDisplayNameRule) Check(runner *tflint.Runner) error {
	log.Printf("[INFO] Check `%s` rule for `%s` runner", r.Name(), runner.TFConfigPath())

	return runner.WalkResourceAttributes(r.resourceType, r.attributeName, func(attribute *hcl.Attribute) error {
		var val string
		err := runner.EvaluateExpr(attribute.Expr, &val)

		return runner.EnsureNoError(err, func() error {
			if len(val) > r.max {
				runner.EmitIssue(
					r,
					"display_name must be 100 characters or less",
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
