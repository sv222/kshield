package profile_test

import (
	"testing"

	"github.com/sv222/kshield/internal/check"
	"github.com/sv222/kshield/internal/profile"
	"github.com/sv222/kshield/internal/regtext"
)

func TestDoraProfileValid(t *testing.T) {
	p, err := profile.Load("dora")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, c := range check.All() {
		ids = append(ids, c.ID)
	}
	if err := p.Validate(ids, regtext.Has); err != nil {
		t.Fatal(err)
	}
}
