package eventlogger

import (
	log "github.com/Sirupsen/logrus"

	"github.com/dpw/ambergris/interceptor/events"
)

type EventLogger struct {
	events.DiscardOthers
}

func (EventLogger) Connection(ev *events.Connection) {
	log.Infoln("Connection", ev.Inbound, ev.Outbound)
}

func (EventLogger) HttpExchange(ev *events.HttpExchange) {
	log.Infoln("Http exchange", ev.Inbound, ev.Outbound,
		ev.Request.Method, ev.Request.URL, ev.Response.StatusCode,
		ev.RoundTrip, ev.TotalTime)
}
