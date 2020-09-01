package vcaptcha

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand"
	"sync"

	"github.com/bonedaddy/vcaptcha/ticket"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/jwtauth"
)

type captcha struct {
	valid  bool
	solved bool
	diff   int
}

type VCaptcha struct {
	mux     sync.RWMutex
	tickets map[string]*captcha
	jwt     *jwtauth.JWTAuth
	minDiff int
	maxDiff int
}

func NewVCaptcha(jwtSecret string, minDiff int, maxDiff int) *VCaptcha {
	return &VCaptcha{
		tickets: make(map[string]*captcha),
		minDiff: minDiff,
		maxDiff: maxDiff,
		jwt:     jwtauth.New("HS256", []byte(jwtSecret), nil),
	}
}

func (vp *VCaptcha) Request() ([]byte, error) {
	tick, err := ticket.NewTicket(vp.getDiff())
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(tick)
	if err != nil {
		return nil, err
	}
	vp.mux.Lock()
	vp.tickets[hex.EncodeToString(tick.Seed[:])] = &captcha{true, false, tick.Difficulty}
	vp.mux.Unlock()
	return data, nil
}

func (vp *VCaptcha) Verify(data []byte) (string, error) {
	var tick ticket.Ticket
	if err := json.Unmarshal(data, &tick); err != nil {
		return "", err
	}

	if !vp.diffInRange(tick.Difficulty) {
		return "", errors.New("invalid ticket difficulty")
	}

	var valid, solved, okDiff bool
	vp.mux.RLock()
	encodedSeed := hex.EncodeToString(tick.Seed[:])
	if vp.tickets[hex.EncodeToString(tick.Seed[:])] != nil {
		valid = vp.tickets[encodedSeed].valid
		solved = vp.tickets[encodedSeed].solved
		// make sure the difficulty of the ticket is what we gave the client
		// this will prevent attacks with people requesting a captcha and solving it using a low difficulty
		okDiff = vp.tickets[encodedSeed].diff == tick.Difficulty
	} else {
		valid = false
	}
	vp.mux.RUnlock()
	if !valid || !okDiff || solved {
		return "", errors.New("invalid ticket given")
	}
	if !tick.Verify(tick.Proof) {
		return "", errors.New("captcha verification failed")
	}

	uuid, err := ticket.IDFromBytes32(tick.Seed)
	if err != nil {
		return "", errors.New("invalid uuid")
	}

	_, tokenString, err := vp.jwt.Encode(jwt.MapClaims{"uuid": uuid.String()})
	if err != nil {
		return "", errors.New("failed to generate jwt")
	}
	vp.mux.Lock()
	vp.tickets[encodedSeed].solved = true
	vp.mux.Unlock()
	return tokenString, nil
}

func (vp *VCaptcha) diffInRange(diff int) bool {
	if diff > vp.maxDiff || diff < vp.minDiff {
		return false
	}
	return true
}

func (vp *VCaptcha) getDiff() int {
	return rand.Intn(vp.maxDiff-vp.minDiff+1) + vp.minDiff
}
