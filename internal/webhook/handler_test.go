package webhook

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrorResponse(t *testing.T) {
	t.Parallel()

	resp := errorResponse(fmt.Errorf("test error"))

	assert.False(t, resp.Allowed)
	assert.Equal(t, int32(http.StatusInternalServerError), resp.Result.Code)
	assert.Equal(t, "test error", resp.Result.Message)
}

func TestHandleHealthz(t *testing.T) {
	t.Parallel()

	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	s.handleHealthz(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ok", rec.Body.String())
}
