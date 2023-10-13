package extension

import (
	"bytes"

	"golang.org/x/crypto/ssh"
)

const EXT_NAME_SESSION_BIND = "session-bind@openssh.com"

type SessionBind struct {
	Hostkey           []byte
	SessionIdentifier []byte
	Signature         []byte
	IsForwarding      bool
}

func (s *SessionBind) Matching(sessionId []byte) bool {
	return bytes.Equal(s.SessionIdentifier, sessionId)
}

func ParseSessionBind(data []byte) (SessionBind, error) {
	var sessionBind SessionBind
	err := ssh.Unmarshal(data, &sessionBind)
	return sessionBind, err
}
