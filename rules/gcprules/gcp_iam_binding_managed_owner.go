package gcprules

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/issue"
	"github.com/wata727/tflint/tflint"
)

// GcpIAMBindingManagedOwnerRule checks whether the owner role is managed by terraform
type GcpIAMBindingManagedOwnerRule struct {
	resourceType   string
	attributeName  string
}

// NewGcpIAMBindingManagedOwnerRule returns new rule with default attributes
func NewGcpIAMBindingManagedOwnerRule() *GcpIAMBindingManagedOwnerRule{
	return &GcpIAMBindingManagedOwnerRule{
		resourceType:   "google_project_iam_binding",
		attributeName:  "role",
	}
}

// Name returns the rule name
func (r *GcpIAMBindingManagedOwnerRule) Name() string {
	return "gcp_iam_binding_managed_owner"
}

// Enabled returns whether the rule is enabled by default
func (r *GcpIAMBindingManagedOwnerRule) Enabled() bool {
	return true
}

// Type returns the rule severity
func (r *GcpIAMBindingManagedOwnerRule) Type() string {
	return issue.WARNING
}

// Link returns the rule reference link
func (r *GcpIAMBindingManagedOwnerRule) Link() string {
	return ""
}

// Check checks whether `roles/owner` is managed by terraform
func (r *GcpIAMBindingManagedOwnerRule) Check(runner *tflint.Runner) error {
	log.Printf("[INFO] Check `%s` rule for `%s` runner", r.Name(), runner.TFConfigPath())

	return runner.WalkResourceAttributes(r.resourceType, r.attributeName, func(attribute *hcl.Attribute) error {
    var val string;
    err := runner.EvaluateExpr(attribute.Expr, &val);

    return runner.EnsureNoError(err, func() error {
      if val == "roles/owner" {
        runner.EmitIssue(
          r,
          "managing 'roles/owner' with Terraform could potentially lock you out of the project",
          attribute.Expr.Range(),
        )
      }
      return nil
    })
	})
}
