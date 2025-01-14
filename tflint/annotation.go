package tflint

import (
	"fmt"
	"regexp"

	"github.com/hashicorp/hcl2/hcl/hclsyntax"
	"github.com/wata727/tflint/issue"
)

var annotationPattern = regexp.MustCompile(`tflint-ignore: (\S+)`)

// Annotation represents comments with special meaning in TFLint
type Annotation struct {
	Content string
	Token   hclsyntax.Token
}

// Annotations is slice of Annotation
type Annotations []Annotation

// NewAnnotations find annotations from the passed tokens and return that list.
func NewAnnotations(tokens hclsyntax.Tokens) Annotations {
	ret := Annotations{}

	for _, token := range tokens {
		if token.Type != hclsyntax.TokenComment {
			continue
		}

		match := annotationPattern.FindStringSubmatch(string(token.Bytes))
		if len(match) != 2 {
			continue
		}
		ret = append(ret, Annotation{
			Content: match[1],
			Token:   token,
		})
	}

	return ret
}

// IsAffected checks if the passed issue is affected with the annotation
func (a *Annotation) IsAffected(issue *issue.Issue) bool {
	if a.Token.Range.Filename != issue.File {
		return false
	}
	if a.Content == issue.Detector || a.Content == "all" {
		if a.Token.Range.Start.Line == issue.Line {
			return true
		}
		if a.Token.Range.Start.Line == issue.Line-1 {
			return true
		}
	}
	return false
}

// String returns the string representation of the annotation
func (a *Annotation) String() string {
	return fmt.Sprintf("annotation:%s (%s)", a.Content, a.Token.Range.String())
}
