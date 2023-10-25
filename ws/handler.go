package ws

import (
	"github.com/gorilla/websocket"
	"net/http"
)

var DefaultUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type HandlerFunc func(*websocket.Conn)

type Handler struct {
	handler  HandlerFunc
	Upgrader websocket.Upgrader
}

func NewHandler(h HandlerFunc) *Handler {
	return &Handler{handler: h, Upgrader: DefaultUpgrader}
}

func (h Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	if DefaultUpgrader.CheckOrigin != nil && DefaultUpgrader.CheckOrigin(req) == false {
		return
	}
	rh := http.Header{}
	conn, err := DefaultUpgrader.Upgrade(w, req, rh)
	if err != nil {
		return
	}
	h.handler(conn)
}
