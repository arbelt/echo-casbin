package casbin_mw

import (
	"net/http"

	"github.com/casbin/casbin/v2"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type UserFn func(echo.Context) string

type Config struct {
	Skipper  middleware.Skipper
	Enforcer *casbin.Enforcer
	UserFunc UserFn
}

func BasicAuthUsername(c echo.Context) string {
	username, _, _ := c.Request().BasicAuth()
	return username
}

var DefaultConfig = Config{
	Skipper:  middleware.DefaultSkipper,
	UserFunc: BasicAuthUsername,
}

func New(config Config) echo.MiddlewareFunc {
	if config.Skipper == nil {
		config.Skipper = middleware.DefaultSkipper
	}

	if config.UserFunc == nil {
		config.UserFunc = BasicAuthUsername
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if config.Skipper(c) {
				return next(c)
			}

			if pass, err := config.CheckPermission(c); err == nil && pass {
				return next(c)
			} else if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
			}

			return echo.ErrForbidden
		}
	}
}

func (config *Config) CheckPermission(c echo.Context) (bool, error) {
	req := c.Request()
	user := config.UserFunc(c)
	method := req.Method
	path := req.URL.Path
	return config.Enforcer.Enforce(user, path, method)
}
