package main

// A line-based unified diff, so the operator sees the exact file change before
// it is installed.
//
// The authorization delta says what a change *means*; this says what it *is*.
// Both are shown, because they answer different questions and neither
// substitutes for the other: a delta with no entries still deserves a diff (the
// edit may be a description change, or a rule that happens to grant nothing new),
// and a one-line diff can carry a large delta.
//
// This is implemented here rather than shelling out to diff(1) for the same
// reason the backends shell out but this does not: diff(1) would need both sides
// on disk, and the candidate half of a `policy grant` comparison should not have
// to be written anywhere before the operator has approved it.

import (
	"fmt"
	"strings"
)

// unifiedDiff renders the change from a to b in unified format with the given
// number of context lines. It returns the empty string when the two are equal.
func unifiedDiff(a, b []string, aName, bName string, context int) string {
	ops := diffOps(a, b)
	if !hasChange(ops) {
		return ""
	}

	var out strings.Builder
	fmt.Fprintf(&out, "--- %s\n+++ %s\n", aName, bName)

	for _, h := range hunks(ops, context) {
		aStart, aLen, bStart, bLen := hunkRange(ops[h.from:h.to])
		fmt.Fprintf(&out, "@@ -%d,%d +%d,%d @@\n", aStart, aLen, bStart, bLen)
		for _, op := range ops[h.from:h.to] {
			switch op.kind {
			case opEqual:
				fmt.Fprintf(&out, " %s\n", op.text)
			case opDelete:
				fmt.Fprintf(&out, "-%s\n", op.text)
			case opInsert:
				fmt.Fprintf(&out, "+%s\n", op.text)
			}
		}
	}
	return out.String()
}

type opKind int

const (
	opEqual opKind = iota
	opDelete
	opInsert
)

type diffOp struct {
	kind opKind
	text string
	// aLine and bLine are 1-based line numbers in each side, 0 where the line
	// does not exist on that side.
	aLine, bLine int
}

// diffOps computes the edit script from a to b via a longest-common-subsequence
// table.
//
// O(len(a)·len(b)) in time and space. That is the wrong algorithm for large
// files and exactly the right one here: a policy is tens to a few hundred lines,
// and the quadratic table is far easier to be confident in than an
// implementation of Myers, on a code path whose output an operator is about to
// approve a credential-policy change from.
func diffOps(a, b []string) []diffOp {
	n, m := len(a), len(b)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}

	var ops []diffOp
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			ops = append(ops, diffOp{opEqual, a[i], i + 1, j + 1})
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			ops = append(ops, diffOp{opDelete, a[i], i + 1, 0})
			i++
		default:
			ops = append(ops, diffOp{opInsert, b[j], 0, j + 1})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, diffOp{opDelete, a[i], i + 1, 0})
	}
	for ; j < m; j++ {
		ops = append(ops, diffOp{opInsert, b[j], 0, j + 1})
	}
	return ops
}

func hasChange(ops []diffOp) bool {
	for _, op := range ops {
		if op.kind != opEqual {
			return true
		}
	}
	return false
}

type hunkSpan struct{ from, to int }

// hunks groups the edit script into runs of change plus surrounding context,
// merging runs that are close enough that their context overlaps.
func hunks(ops []diffOp, context int) []hunkSpan {
	var out []hunkSpan
	i := 0
	for i < len(ops) {
		if ops[i].kind == opEqual {
			i++
			continue
		}
		// Walk back over the leading context.
		from := max(i-context, 0)
		// Walk forward to the end of this run of changes, absorbing any run of
		// equal lines short enough to sit inside two context windows.
		to := i
		for to < len(ops) {
			if ops[to].kind != opEqual {
				to++
				continue
			}
			gap := 0
			for to+gap < len(ops) && ops[to+gap].kind == opEqual {
				gap++
			}
			if to+gap >= len(ops) || gap > context*2 {
				break
			}
			to += gap
		}
		to = min(to+context, len(ops))

		// Merge with the previous hunk if they now touch or overlap.
		if len(out) > 0 && from <= out[len(out)-1].to {
			out[len(out)-1].to = to
		} else {
			out = append(out, hunkSpan{from, to})
		}
		i = to
	}
	return out
}

// hunkRange returns the 1-based start line and length of a hunk on each side, in
// the form a unified-diff header expects.
func hunkRange(ops []diffOp) (aStart, aLen, bStart, bLen int) {
	for _, op := range ops {
		if op.aLine > 0 {
			if aStart == 0 {
				aStart = op.aLine
			}
			aLen++
		}
		if op.bLine > 0 {
			if bStart == 0 {
				bStart = op.bLine
			}
			bLen++
		}
	}
	// A hunk that only inserts has no line on the a side; unified diff writes
	// the position it was inserted after, with length 0.
	if aStart == 0 {
		aStart = ops[0].bLine
	}
	if bStart == 0 {
		bStart = ops[0].aLine
	}
	return aStart, aLen, bStart, bLen
}

// splitLines splits rendered file bytes into lines, dropping the trailing empty
// element a final newline produces. Marshal always terminates with a newline, so
// without this every diff would carry a spurious blank line.
func splitLines(b []byte) []string {
	s := strings.TrimSuffix(string(b), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
