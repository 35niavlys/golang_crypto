package extension

import (
	"bytes"
	"fmt"
)

type SignData struct {
	Session   []byte
	Type      byte
	User      string
	Service   string
	Method    string
	Sign      bool
	Algo      string
	PubKey    []byte
	HostKey   []byte
	Signature []byte
}

func ParseSignData(data []byte, expectedKey []byte) (signData SignData, err error) {
	signData = SignData{}
	var tempArray []byte

	var ok bool
	// Session
	if signData.Session, data, ok = parseString(data); !ok {
		return signData, errShortRead
	}
	// Type
	signData.Type = data[0]
	data = data[1:]
	// User
	if tempArray, data, ok = parseString(data); !ok {
		return signData, errShortRead
	}
	signData.User = string(tempArray)
	// Service
	if tempArray, data, ok = parseString(data); !ok {
		return signData, errShortRead
	}
	signData.Service = string(tempArray)
	// Method
	if tempArray, data, ok = parseString(data); !ok {
		return signData, errShortRead
	}
	signData.Method = string(tempArray)
	// Sign
	signData.Sign = data[0] != 0
	data = data[1:]
	// Algo
	if tempArray, data, ok = parseString(data); !ok {
		return signData, errShortRead
	}
	signData.Algo = string(tempArray)

	// Key or Host
	var key []byte
	if key, data, ok = parseString(data); !ok {
		return signData, errShortRead
	}

	if signData.Type != 50 ||
		!signData.Sign ||
		signData.Service != "ssh-connection" ||
		!bytes.Equal(expectedKey, key) {
		return signData, fmt.Errorf("ssh: invalid sign data")
	}

	if signData.Method == "publickey-hostbound-v00@openssh.com" {
		signData.PubKey = key
		if signData.HostKey, _, ok = parseString(data); !ok {
			return signData, errShortRead
		}
	} else if signData.Method == "publickey" {
		signData.HostKey = key
	} else {
		return signData, fmt.Errorf("ssh: invalid method sign data")
	}

	return signData, err
}
