// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/issue"
	"github.com/wata727/tflint/tflint"
)

// AwsGuarddutyDetectorInvalidFindingPublishingFrequencyRule checks the pattern is valid
type AwsGuarddutyDetectorInvalidFindingPublishingFrequencyRule struct {
	resourceType  string
	attributeName string
	enum          []string
}

// NewAwsGuarddutyDetectorInvalidFindingPublishingFrequencyRule returns new rule with default attributes
func NewAwsGuarddutyDetectorInvalidFindingPublishingFrequencyRule() *AwsGuarddutyDetectorInvalidFindingPublishingFrequencyRule {
	return &AwsGuarddutyDetectorInvalidFindingPublishingFrequencyRule{
		resourceType:  "aws_guardduty_detector",
		attributeName: "finding_publishing_frequency",
		enum: []string{
			"FIFTEEN_MINUTES",
			"ONE_HOUR",
			"SIX_HOURS",
		},
	}
}

// Name returns the rule name
func (r *AwsGuarddutyDetectorInvalidFindingPublishingFrequencyRule) Name() string {
	return "aws_guardduty_detector_invalid_finding_publishing_frequency"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsGuarddutyDetectorInvalidFindingPublishingFrequencyRule) Enabled() bool {
	return true
}

// Type returns the rule severity
func (r *AwsGuarddutyDetectorInvalidFindingPublishingFrequencyRule) Type() string {
	return issue.ERROR
}

// Link returns the rule reference link
func (r *AwsGuarddutyDetectorInvalidFindingPublishingFrequencyRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsGuarddutyDetectorInvalidFindingPublishingFrequencyRule) Check(runner *tflint.Runner) error {
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
					`finding_publishing_frequency is not a valid value`,
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
