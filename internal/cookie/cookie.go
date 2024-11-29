package cookie

import (
	"errors"
	"net/http"
	"time"
)

// CookieStore interface defines methods for setting and getting cookies
type CookieStore interface {
	SetCookie(name, value string)
	GetCookie(name string) (string, error)
	DeleteCookie(name string)
}

// CookieStoreImpl is a concrete implementation of the CookieStore interface
type CookieStoreImpl struct {
	writer  http.ResponseWriter
	request *http.Request
	secure  bool
}

// NewCookieStore creates a new instance of CookieStoreImpl
func NewCookieStore(w http.ResponseWriter, r *http.Request, secure bool) *CookieStoreImpl {
	return &CookieStoreImpl{
		writer:  w,
		request: r,
		secure:  secure,
	}
}

// SetCookie sets a cookie with the given name, value, and attributes
func (c *CookieStoreImpl) SetCookie(name, value string) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Secure:   c.secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(c.writer, cookie)
}

// DeleteCookie removes a cookie with the given name
func (c *CookieStoreImpl) DeleteCookie(name string) {
	cookie := &http.Cookie{
		Name:    name,
		Value:   "",
		Path:    "/",
		MaxAge:  -1,
		Expires: time.Unix(0, 0),
	}

	http.SetCookie(c.writer, cookie)
}

// GetCookie retrieves the value of the cookie with the given name
func (c *CookieStoreImpl) GetCookie(name string) (string, error) {
	cookie, err := c.request.Cookie(name)
	if err != nil {
		return "", errors.New("cookie not found")
	}
	return cookie.Value, nil
}
