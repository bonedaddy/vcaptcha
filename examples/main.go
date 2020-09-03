package main

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bonedaddy/vcaptcha"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/jwtauth"
)

const (
	listenAddr = "localhost:6969"
)

type server struct {
	srv  *http.Server
	vcap *vcaptcha.VCaptcha
	mux  sync.RWMutex
}

func main() {
	r := chi.NewRouter()
	r.Use(middleware.DefaultLogger)
	r.Use(middleware.Recoverer)
	srv := &server{
		vcap: vcaptcha.NewVCaptcha("1", 100, 200),
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
	srv.srv.ListenAndServe()

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
