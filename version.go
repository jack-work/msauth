package msauth

import (
	"strconv"
	"strings"
)

// A floor may now name a SEMANTIC VERSION as well as a git revision, because a
// client that consumes this module normally -- `require github.com/jack-work/
// msauth v0.1.0` -- has no git revision to name. Its build info records the
// module version and nothing else, which is the whole point of converging on a
// published module: go.mod and go.sum are the provenance, verified by the
// toolchain rather than by a link-time stamp somebody has to remember to set.
//
// The two floor dialects are kept apart deliberately rather than unified. A
// revision floor answers "is this artifact's foundation an ancestor-or-self of
// the one my source needs", which only git can decide. A version floor answers
// "is this artifact's foundation at least this release", which is arithmetic.
// Guessing which question was asked from a bare string is exactly the kind of
// inference that produces a confident wrong answer, so the SHAPE of the floor
// selects the comparison and a malformed floor is an error, never a pass.

// plausibleVersion reports whether text is a semantic version of the shape Go
// module versions take: a leading v, three dot-separated numbers, and an
// optional pre-release suffix.
//
// Build metadata (+incompatible, +dirty) is rejected on purpose. A floor is
// something a human commits, and every meaning a + suffix could carry here is
// one the revision dialect already expresses better.
func plausibleVersion(text string) bool {
	_, ok := parseVersion(text)
	return ok
}

type parsedVersion struct {
	numbers    [3]int
	preRelease string
}

func parseVersion(text string) (parsedVersion, bool) {
	var parsed parsedVersion
	if !strings.HasPrefix(text, "v") {
		return parsed, false
	}
	rest := text[1:]
	if strings.Contains(rest, "+") {
		return parsed, false
	}
	if dash := strings.Index(rest, "-"); dash >= 0 {
		parsed.preRelease = rest[dash+1:]
		rest = rest[:dash]
		if parsed.preRelease == "" {
			return parsed, false
		}
	}
	fields := strings.Split(rest, ".")
	if len(fields) != 3 {
		return parsed, false
	}
	for i, field := range fields {
		if field == "" || (len(field) > 1 && field[0] == '0') {
			return parsed, false
		}
		number, err := strconv.Atoi(field)
		if err != nil || number < 0 {
			return parsed, false
		}
		parsed.numbers[i] = number
	}
	return parsed, true
}

// compareSemver returns -1, 0 or 1. (compareVersions is taken: broker.go orders
// the PowerShell module's dotted version, a different and looser question.) A pre-release sorts BEFORE the release it
// qualifies, as semver requires: v0.2.0-rc.1 is older than v0.2.0. Two
// pre-releases of the same version are compared as plain strings, which is not
// full semver pre-release ordering and does not pretend to be -- see
// SemverOrdering, which refuses to answer in that case rather than guess.
func compareSemver(left, right parsedVersion) int {
	for i := range left.numbers {
		switch {
		case left.numbers[i] < right.numbers[i]:
			return -1
		case left.numbers[i] > right.numbers[i]:
			return 1
		}
	}
	switch {
	case left.preRelease == right.preRelease:
		return 0
	case left.preRelease == "":
		return 1
	case right.preRelease == "":
		return -1
	}
	return strings.Compare(left.preRelease, right.preRelease)
}

// SemverOrdering is the Ordering for a version floor: it reports whether the
// carried version is at or after the required one.
//
// It returns known=false for anything it cannot decide rather than guessing,
// which is what keeps a floor honest: an unknown ordering falls through to
// exact equality in AuditAtLeast, the stricter answer. Two different
// pre-releases of the same version are the case it declines, because correct
// pre-release precedence is fiddly and a wrong answer here would silently pass
// an artifact built from an older release candidate.
func SemverOrdering() Ordering {
	return func(required, carried string) (bool, bool) {
		wanted, ok := parseVersion(required)
		if !ok {
			return false, false
		}
		held, ok := parseVersion(carried)
		if !ok {
			return false, false
		}
		if wanted.preRelease != "" && held.preRelease != "" && wanted.preRelease != held.preRelease {
			return false, false
		}
		return compareSemver(held, wanted) >= 0, true
	}
}
