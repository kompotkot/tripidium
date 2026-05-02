package organizations

import (
	"github.com/kompotkot/tripidium/internal/transport/runtime"
)

type Handler struct {
	deps runtime.Dependencies
}

func NewHandler(deps runtime.Dependencies) *Handler {
	return &Handler{deps: deps}
}
