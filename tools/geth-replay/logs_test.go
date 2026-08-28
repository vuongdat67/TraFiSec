package main

import (
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
)

func TestTargetLogsExcludesPrefixLogs(t *testing.T) {
	prefix := []*types.Log{{Index: 1}, {Index: 2}, {Index: 3}, {Index: 4}}
	target := []*types.Log{{Index: 5}, {Index: 6}}
	all := append(prefix, target...)

	got := targetLogs(all, len(prefix))
	if len(got) != len(target) || got[0].Index != 5 || got[1].Index != 6 {
		t.Fatalf("target logs = %#v, want target-only suffix", got)
	}
}

func TestTargetLogsEmptyWhenTargetEmitsNoLogs(t *testing.T) {
	prefix := []*types.Log{{Index: 1}, {Index: 2}}
	got := targetLogs(prefix, len(prefix))
	if len(got) != 0 {
		t.Fatalf("target logs = %#v, want empty target log set", got)
	}
}

func TestTargetLogsRejectsInvalidPrefixCount(t *testing.T) {
	logs := []*types.Log{{Index: 1}}
	for _, prefixCount := range []int{-1, 2} {
		if got := targetLogs(logs, prefixCount); got != nil {
			t.Fatalf("target logs for prefix count %d = %#v, want nil", prefixCount, got)
		}
	}
}
