package vcaptcha

import (
	"math/rand"
	"testing"

	"github.com/bonedaddy/vcaptcha/ticket"
	"github.com/stretchr/testify/require"
)

// todo: refine, this is just a quick test
func TestVCaptcha(t *testing.T) {
	cap := NewVCaptcha("1", 100, 200)
	require.NotNil(t, cap)

	tickBytes, err := cap.Request()
	require.NoError(t, err)

	tick, err := ticket.FromBytes(tickBytes)
	require.NoError(t, err)

	tick.Solve()

	tickBytes, err = tick.Marshal()
	require.NoError(t, err)

	_, err = cap.Verify(tickBytes)
	require.NoError(t, err)

	// test an invalid proof
	tickBytes, err = cap.Request()
	require.NoError(t, err)

	tick, err = ticket.FromBytes(tickBytes)
	require.NoError(t, err)

	_, err = rand.Read(tick.Proof[:])
	require.NoError(t, err)

	tickBytes, err = tick.Marshal()
	require.NoError(t, err)

	_, err = cap.Verify(tickBytes)
	require.Error(t, err)

	require.False(t, cap.diffInRange(0))
	require.True(t, cap.diffInRange(199))
	require.False(t, cap.diffInRange(1000))
	require.True(t, cap.diffInRange(cap.getDiff()))

}
