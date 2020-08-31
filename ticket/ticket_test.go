package ticket

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTicket(t *testing.T) {
	tick, err := NewTicket(100)
	require.NoError(t, err)
	proof := tick.Solve()
	require.True(t, tick.Verify(proof))
}
