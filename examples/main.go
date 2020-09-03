package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bonedaddy/vcaptcha"
	"github.com/bonedaddy/vcaptcha/ticket"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/jwtauth"
)

const (
	listenAddr = "localhost:6969"
)

var (
	minDiff = flag.Int("min-diff", 100, "minimum difficulty set to 5000+ for difficult computations")
	maxDiff = flag.Int("max-diff", 200, "maximum difficulty to use, should be at least equal to min-diff")
)

type server struct {
	srv  *http.Server
	vcap *vcaptcha.VCaptcha
	mux  sync.RWMutex
}

func init() {
	flag.Parse()
}

func main() {
	r := chi.NewRouter()
	r.Use(middleware.DefaultLogger)
	r.Use(middleware.Recoverer)
	srv := &server{
		vcap: vcaptcha.NewVCaptcha("1", *minDiff, *maxDiff),
	}
	r.Get("/captcha_request", srv.CaptchaRequest)
	r.Post("/captcha_solve", srv.CaptchaSolve)
	// group protected routes guarded by needing a JWT
	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(srv.vcap.JWT()))
		r.Use(jwtauth.Authenticator)
		// while this is an example the general idea is that you would leverage this wildcard route
		// to proxy requests to your backend
		r.HandleFunc("/protected/*", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("hello world"))
		})
	})
	srv.srv = &http.Server{
		Handler: r,
		Addr:    listenAddr,
	}
	go srv.srv.ListenAndServe()
	defer func() {
		srv.srv.Close()
	}()
	fmt.Println("giving time for server to start")
	time.Sleep(time.Second)

	// create a http client
	hc := &http.Client{}

	// send a request to retrieve a ticket to solve
	resp, err := hc.Get("http://" + listenAddr + "/captcha_request")
	if err != nil {
		log.Fatal(err)
	}

	// read response body containing marshalled ticket data
	data, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Fatal(err)
	}

	// unmarshal the ticket
	tick, err := ticket.FromBytes(data)
	if err != nil {
		log.Fatal(err)
	}

	// compute the vdf which will update the ticket struct
	// to contain the proof of the VDF computation
	tick.Solve()

	// remarshal the updated ticket containing the proof
	tickData, err := tick.Marshal()
	if err != nil {
		log.Fatal(err)
	}

	// create a request to send the solved ticket
	req, err := http.NewRequest("POST", "http://"+listenAddr+"/captcha_solve", bytes.NewReader(tickData))
	if err != nil {
		log.Fatal(err)
	}

	// send the request
	resp, err = hc.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	// read the resposne
	data, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("solved ticket and received jwt: ", string(data))

	// create a request to test our the JWT and access to restricted functions
	req, err = http.NewRequest("POST", "http://"+listenAddr+"/protected/test", nil)
	if err != nil {
		log.Fatal(err)
	}

	// se the JWT authorization header
	req.Header.Set("Authorization", "BEARER "+string(data))

	// send the request
	resp, err = hc.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	// read the response data
	data, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Fatal(err)
	}

	// validate that the returned data is as expected
	if string(data) != "hello world" {
		log.Fatal("failed to send request to protected route")
	}

	fmt.Println("successfully sent request to protected route")
}

func (s *server) CaptchaRequest(w http.ResponseWriter, r *http.Request) {
	tickData, err := s.vcap.Request()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(tickData))
}

func (s *server) CaptchaSolve(w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jwtString, err := s.vcap.Verify(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.ServeContent(w, r, "", time.Time{}, strings.NewReader(jwtString))

}
