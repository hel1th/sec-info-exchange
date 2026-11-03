package httptransport

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/hel1th/sec-info-exchange/internal/api/generated"
	"github.com/hel1th/sec-info-exchange/internal/domain"
	"github.com/hel1th/sec-info-exchange/internal/usecase"
)

// ThreatService is the application interface consumed by the HTTP adapter.
type ThreatService interface {
	Create(context.Context, usecase.CreateThreatInput) (usecase.CreateThreatOutput, error)
	Get(context.Context, usecase.GetThreatInput) (usecase.GetThreatOutput, error)
	Update(context.Context, usecase.UpdateThreatInput) (usecase.UpdateThreatOutput, error)
}

type handler struct{ threats ThreatService }

func (h handler) get(w http.ResponseWriter, r *http.Request) {
	t, err := h.threats.Get(r.Context(), usecase.GetThreatInput{MD5: chi.URLParam(r, "md5")})
	respond(w, r, http.StatusOK, usecase.ThreatOutput(t), err)
}

func (h handler) create(w http.ResponseWriter, r *http.Request) {
	var req generated.ThreatCreateRequest
	if !decode(w, r, &req) {
		return
	}
	t, err := h.threats.Create(r.Context(), toCreateInput(req))
	respond(w, r, http.StatusCreated, usecase.ThreatOutput(t), err)
}

func (h handler) update(w http.ResponseWriter, r *http.Request) {
	var req generated.ThreatUpdateRequest
	if !decode(w, r, &req) {
		return
	}
	t, err := h.threats.Update(r.Context(), toUpdateInput(chi.URLParam(r, "md5"), req))
	respond(w, r, http.StatusOK, usecase.ThreatOutput(t), err)
}

func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(dst); err != nil {
		writeDecodeError(w, err)
		return false
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		writeDecodeError(w, err)
		return false
	}
	return true
}

func writeDecodeError(w http.ResponseWriter, err error) {
	if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
		writeJSON(w, http.StatusRequestEntityTooLarge, generated.ErrorResponse{Message: "Request body too large"})
		return
	}
	writeJSON(w, http.StatusBadRequest, generated.ErrorResponse{Message: "Expected a single valid JSON object"})
}

func respond(w http.ResponseWriter, r *http.Request, status int, t usecase.ThreatOutput, err error) {
	if err == nil {
		writeJSON(w, status, toThreatResponse(t))
		return
	}
	var message string
	switch {
	case errors.Is(err, domain.ErrInvalid):
		status, message = http.StatusBadRequest, "Invalid threat data"
	case errors.Is(err, usecase.ErrNotFound):
		status, message = http.StatusNotFound, "Threat not found"
	case errors.Is(err, usecase.ErrConflict):
		status, message = http.StatusConflict, "Threat already exists"
	default:
		status, message = http.StatusInternalServerError, "Internal server error"
		slog.ErrorContext(r.Context(), "threat operation failed", "error", err)
	}
	writeJSON(w, status, generated.ErrorResponse{Message: message})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
