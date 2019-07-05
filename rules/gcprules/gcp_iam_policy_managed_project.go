package gcprules

import (
	"log"

	"github.com/wata727/tflint/issue"
	"github.com/wata727/tflint/tflint"
)

// GcpIAMPolicyManagedProject checks whether the owner role is managed by terraform
type GcpIAMPolicyManagedProject struct {
	resourceType   string
}

// NewGcpIAMPolicyManagedProject returns new rule with default attributes
func NewGcpIAMPolicyManagedProject() *GcpIAMPolicyManagedProject{
	return &GcpIAMPolicyManagedProject{
		resourceType:   "google_project_iam_policy",
	}
}

// Name returns the rule name
func (r *GcpIAMPolicyManagedProject) Name() string {
	return "gcp_iam_policy_managed_project"
}

// Enabled returns whether the rule is enabled by default
func (r *GcpIAMPolicyManagedProject) Enabled() bool {
	return true
}

// Type returns the rule severity
func (r *GcpIAMPolicyManagedProject) Type() string {
	return issue.WARNING
}

// Link returns the rule reference link
func (r *GcpIAMPolicyManagedProject) Link() string {
	return ""
}

// Check checks whether google_project_iam_policy is used
func (r *GcpIAMPolicyManagedProject) Check(runner *tflint.Runner) error {
	log.Printf("[INFO] Check `%s` rule for `%s` runner", r.Name(), runner.TFConfigPath())

  for _, resource := range runner.LookupResourcesByType(r.resourceType) {
    runner.EmitIssue(
      r,
      "managing the IAM policy using google_project_iam_policy can potentially lock you out of the project",
      resource.DeclRange,
    )
  }
  return nil;
}
