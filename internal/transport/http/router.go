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
	router := chi.NewRouter()

	router.Use(middleware.GetHead)
	router.Use(middleware.Logger)
	router.Use(middleware.CleanPath)
	router.Use(middleware.StripSlashes)

	router.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, probeResponse{Status: "ok"})
	})

	h := handler{threats: service}
	router.Get("/info/{md5}", h.get)
	router.Post("/info", h.create)
	router.Put("/info/{md5}", h.update)
	return router
}
