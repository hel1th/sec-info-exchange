// Package httptransport implements the HTTP boundary of the service.
package httptransport

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// NewHandler creates API routes backed by service, which must not be nil.
// Health checks only confirm process liveness.
func NewHandler(service ThreatService) http.Handler {
	mux := chi.NewRouter()
	mux.Use(middleware.GetHead)
	mux.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, probeResponse{Status: "ok"})
	})
	h := handler{threats: service}
	mux.Get("/info/{md5}", h.get)
	mux.Post("/info", h.create)
	mux.Put("/info/{md5}", h.update)
	return mux
}
