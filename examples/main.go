package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bonedaddy/vcaptcha"
	"github.com/bonedaddy/vcaptcha/ticket"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
)

const (
	listenAddr = "localhost:6969"
)

type captcha struct {
	valid  bool
	solved bool
	diff   int
}

type server struct {
	srv     *http.Server
	vcap    *vcaptcha.VCaptcha
	mux     sync.RWMutex
	tickets map[string]*captcha
}

func main() {
	r := chi.NewRouter()
	r.Use(middleware.DefaultLogger)
	r.Use(middleware.Recoverer)
	srv := &server{
		vcap:    vcaptcha.NewVCaptcha("1", 100, 200),
		tickets: make(map[string]*captcha),
	}
	r.Get("/captcha_request", srv.CaptchaRequest)
	r.Post("/captcha_solve", srv.CaptchaSolve)
	srv.srv = &http.Server{
		Handler: r,
		Addr:    listenAddr,
	}
	srv.srv.ListenAndServe()

}

func (s *server) CaptchaRequest(w http.ResponseWriter, r *http.Request) {
	tick, err := ticket.NewTicket(s.vcap.GetDiff())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data, err := json.Marshal(tick)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.mux.Lock()
	s.tickets[hex.EncodeToString(tick.Seed[:])] = &captcha{true, false, tick.Difficulty}
	s.mux.Unlock()
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(data))
}

func (s *server) CaptchaSolve(w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var tick ticket.Ticket
	if err := json.Unmarshal(data, &tick); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !s.vcap.DiffInRange(tick.Difficulty) {
		http.Error(w, "invalid difficulty given", http.StatusBadRequest)
		return
	}

	var valid, solved, okDiff bool
	s.mux.RLock()
	encodedSeed := hex.EncodeToString(tick.Seed[:])
	if s.tickets[hex.EncodeToString(tick.Seed[:])] != nil {
		valid = s.tickets[encodedSeed].valid
		solved = s.tickets[encodedSeed].solved
		// make sure the difficulty of the ticket is what we gave the client
		// this will prevent attacks with people requesting a captcha and solving it using a low difficulty
		okDiff = s.tickets[encodedSeed].diff == tick.Difficulty
	} else {
		valid = false
	}
	s.mux.RUnlock()
	if !valid || !okDiff || solved {
		http.Error(w, "invalid ticket given", http.StatusBadRequest)
		return
	}

	if !tick.Verify(tick.Proof) {
		http.ServeContent(w, r, "", time.Time{}, strings.NewReader("captcha failed"))
		return
	}

	uuid, err := ticket.IDFromBytes32(tick.Seed)
	if err != nil {
		http.Error(w, "invalid ticket seed", http.StatusBadRequest)
		return
	}

	_, tokenString, err := s.vcap.JWT().Encode(jwt.MapClaims{"uuid": uuid.String()})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.ServeContent(w, r, "", time.Time{}, strings.NewReader(tokenString))

	s.mux.Lock()
	s.tickets[encodedSeed].solved = true
	s.mux.Unlock()

}
