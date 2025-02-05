// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/issue"
	"github.com/wata727/tflint/tflint"
)

// AwsElastiCacheClusterInvalidAzModeRule checks the pattern is valid
type AwsElastiCacheClusterInvalidAzModeRule struct {
	resourceType  string
	attributeName string
	enum          []string
}

// NewAwsElastiCacheClusterInvalidAzModeRule returns new rule with default attributes
func NewAwsElastiCacheClusterInvalidAzModeRule() *AwsElastiCacheClusterInvalidAzModeRule {
	return &AwsElastiCacheClusterInvalidAzModeRule{
		resourceType:  "aws_elasticache_cluster",
		attributeName: "az_mode",
		enum: []string{
			"single-az",
			"cross-az",
		},
	}
}

// Name returns the rule name
func (r *AwsElastiCacheClusterInvalidAzModeRule) Name() string {
	return "aws_elasticache_cluster_invalid_az_mode"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsElastiCacheClusterInvalidAzModeRule) Enabled() bool {
	return true
}

// Type returns the rule severity
func (r *AwsElastiCacheClusterInvalidAzModeRule) Type() string {
	return issue.ERROR
}

// Link returns the rule reference link
func (r *AwsElastiCacheClusterInvalidAzModeRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsElastiCacheClusterInvalidAzModeRule) Check(runner *tflint.Runner) error {
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
					`az_mode is not a valid value`,
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
