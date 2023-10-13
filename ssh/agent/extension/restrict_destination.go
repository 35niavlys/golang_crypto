// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package extension

import (
	"bytes"
)

const EXT_NAME_RESTRICT_DESTINATION_00 = "restrict-destination-v00@openssh.com"

type KeySpec struct {
	keyblob []byte
	is_ca   bool
}

type Hop struct {
	Username string
	Hostname string
	reserved []byte
	Hostkeys []KeySpec
}

type DestinationConstraint struct {
	From     Hop
	To       Hop
	reserved []byte
}

/*
func parseKeyspec(data []byte) (KeySpec, error) {
	fmt.Println(data)
	var ks KeySpec
	var ok bool
	if ks.keyblob, _, ok = parseString(data); !ok {
		return ks, errShortRead
	}
	return ks, nil
}*/

func parseHop(data []byte) (Hop, error) {
	var hop Hop
	var ok bool
	var to_use []byte
	{
		if to_use, data, ok = parseString(data); !ok {
			return hop, errShortRead
		}
		hop.Username = string(to_use)
	}
	{
		if to_use, data, ok = parseString(data); !ok {
			return hop, errShortRead
		}
		hop.Hostname = string(to_use)
	}
	{
		if hop.reserved, data, ok = parseString(data); !ok {
			return hop, errShortRead
		}
	}
	{
		for len(data) > 0 {
			var keyspec KeySpec
			if keyspec.keyblob, data, ok = parseString(data); !ok {
				return hop, errShortRead
			}
			if len(data) == 0 {
				return hop, errShortRead
			}
			keyspec.is_ca = data[0] != 0
			data = data[1:]
			hop.Hostkeys = append(hop.Hostkeys, keyspec)
		}
	}

	return hop, nil
}

func parseConstraint(data []byte) (DestinationConstraint, error) {
	var constraint DestinationConstraint
	var datahop []byte
	var ok bool
	var err error
	if datahop, data, ok = parseString(data); !ok {
		return constraint, errShortRead
	}
	if constraint.From, err = parseHop(datahop); err != nil {
		return constraint, err
	}
	if datahop, constraint.reserved, ok = parseString(data); !ok {
		return constraint, errShortRead
	}
	if constraint.To, err = parseHop(datahop); err != nil {
		return constraint, err
	}
	return constraint, nil
}

func ParseRestrictDestinations(data []byte) ([]DestinationConstraint, error) {
	var constraints []DestinationConstraint
	var to_use []byte
	var ok bool

	for len(data) > 0 {
		var constr DestinationConstraint
		var err error
		if to_use, data, ok = parseString(data); !ok {
			return constraints, errShortRead
		}
		if constr, err = parseConstraint(to_use); err != nil {
			return constraints, err
		}
		constraints = append(constraints, constr)
	}

	return constraints, nil
}

func IdentityPermitted(destinationConstraints []DestinationConstraint, sessions []SessionBind, user string) bool {

	if len(destinationConstraints) == 0 {
		return true // unconstrained
	}
	if len(sessions) == 0 {
		return true // local use
	}

	fromkey := []KeySpec(nil)
	/*
	 * Walk through the hops recorded by session_id and try to find a constraint that satisfies each.
	 */
	for i := 0; i < len(sessions); i++ {
		sessionBind := sessions[i]
		testuser := ""
		if i == len(sessions)-1 {
			testuser = user
			if sessionBind.IsForwarding {
				return false // tried to sign on forwarding hop
			}
		} else if !sessionBind.IsForwarding {
			return false // tried to forward though signing bind
		}

		ok := false
		for _, destinationConstraint := range destinationConstraints {
			if destinationConstraint.IdentityPermitted(fromkey, sessionBind.Hostkey, testuser) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
		fromkey = []KeySpec{{keyblob: sessionBind.Hostkey, is_ca: false}}
	}

	/*
	 * Another special case: if the last bound session ID was for a
	 * forwarding, and this function is not being called to check a sign
	 * request (i.e. no 'user' supplied), then only permit the key if
	 * there is a permission that would allow it to be used at another
	 * destination. This hides keys that are allowed to be used to
	 * authenicate *to* a host but not permitted for *use* beyond it.
	 */
	lastBindSession := sessions[len(sessions)-1]
	if lastBindSession.IsForwarding && len(user) == 0 {
		for _, destinationConstraint := range destinationConstraints {
			if destinationConstraint.IdentityPermitted([]KeySpec{{keyblob: lastBindSession.Hostkey, is_ca: false}}, nil, "") {
				return true
			}
		}
		return false
	}
	/* success */
	return true
}

func (d *DestinationConstraint) IdentityPermitted(fromkey []KeySpec, tokey []byte, user string) bool {
	if len(fromkey) == 0 {
		/* We are matching the first hop */
		if len(d.From.Hostname) > 0 || len(d.From.Hostkeys) > 0 {
			return false
		}
	} else {
		for _, hk := range d.From.Hostkeys {
			for _, keySpec := range fromkey {
				if bytes.Equal(hk.keyblob, keySpec.keyblob) {
					goto to
				}
			}
		}
		return false
	}

to:
	/* Match 'to' key */
	if len(tokey) > 0 {
		for _, hk := range d.To.Hostkeys {
			if bytes.Equal(hk.keyblob, tokey) {
				goto user
			}
		}
		return false
	}

user:
	/* Match user if specified */
	// FIXME: sould be a pattern
	if len(d.To.Username) > 0 && len(user) > 0 && d.To.Username != user {
		return false
	}

	return true
}
