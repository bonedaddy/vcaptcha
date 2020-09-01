package vcaptcha

import (
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
}
