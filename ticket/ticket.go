package ticket

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/bonedaddy/vcaptcha/vdf"

	"github.com/segmentio/ksuid"
)

type Ticket struct {
	Seed       [32]byte  `json:"seed"`
	Difficulty int       `json:"difficulty"`
	Proof      [516]byte `json:"proof"`
}

func NewTicket(diff int) (*Ticket, error) {
	seed, err := NewSeed()
	if err != nil {
		return nil, err
	}
	return &Ticket{Seed: seed, Difficulty: diff}, nil
}

func FromBytes(data []byte) (*Ticket, error) {
	var tick Ticket
	if err := json.Unmarshal(data, &tick); err != nil {
		return nil, err
	}
	return &tick, nil
}

func (t *Ticket) Encode() (string, error) {
	data, err := t.Marshal()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

func (t *Ticket) Marshal() ([]byte, error) {
	return json.Marshal(t)
}

func (t *Ticket) Hash() string {
	bytes, err := json.Marshal(t)
	if err != nil {
		return ""
	}
	dt := sha256.Sum256(bytes)
	return hex.EncodeToString(dt[:])
}

func (t *Ticket) Verify(proof [516]byte) bool {
	gvdf := vdf.New(t.Difficulty, t.Seed)
	return gvdf.Verify(proof)
}

func (t *Ticket) Solve() [516]byte {
	gvdf := vdf.New(t.Difficulty, t.Seed)
	gvdf.Execute()
	proof := <-gvdf.GetOutputChannel()
	t.Proof = proof
	return proof
}

func NewSeed() ([32]byte, error) {
	kid, err := ksuid.NewRandom()
	if err != nil {
		return [32]byte{}, err
	}
	return IDToBytes32(kid), nil
}

// IDToBytes32 is used to pad a ksuid to 32 bytes
func IDToBytes32(kid ksuid.KSUID) [32]byte {
	var (
		id       [32]byte
		combined []byte
	)
	combined = append(combined, kid.Bytes()...)
	combined = append(combined, kid.Payload()[0:12]...)
	for i := 0; i < len(combined); i++ {
		id[i] = combined[i]
	}
	return id
}

// IDFromBytes32 converts
func IDFromBytes32(id [32]byte) (ksuid.KSUID, error) {
	var idBytes = make([]byte, 20)
	for k, v := range id {
		if k == 20 {
			break
		}
		idBytes[k] = v
	}
	return ksuid.FromBytes(idBytes)
}
