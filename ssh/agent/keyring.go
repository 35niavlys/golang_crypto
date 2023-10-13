// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent/extension"
)

type SessionsKey struct{}

type privKey struct {
	signer                 ssh.Signer
	comment                string
	expire                 *time.Time
	destinationConstraints []extension.DestinationConstraint
}

type legacyKeyring struct {
	k        ctxKeyring
	dummyCtx context.Context
}

type ctxKeyring struct {
	mu   sync.Mutex
	keys []privKey

	locked     bool
	passphrase []byte
}

var errLocked = errors.New("agent: locked")
var errLegacyAgent = errors.New("agent: please use NewContextKeyring instead of NewKeyring")

// NewKeyring returns an Agent that holds keys in memory.  It is safe
// for concurrent use by multiple goroutines.
// Deprecated: use NewContextKeyring
func NewKeyring() ExtendedAgent {
	return &legacyKeyring{dummyCtx: context.TODO()}
}

func NewContextKeyring() ContextAgent {
	return &ctxKeyring{}
}

func (r *ctxKeyring) InitContext(ctx context.Context) context.Context {
	sessions := make([]extension.SessionBind, 0)
	return context.WithValue(ctx, SessionsKey{}, &sessions)
}

func (r *ctxKeyring) addBindSession(ctx context.Context, sessions ...extension.SessionBind) {
	ctxSessions := ctx.Value(SessionsKey{}).(*[]extension.SessionBind)
	if ctxSessions != nil {
		*ctxSessions = append(*ctxSessions, sessions...)
	}
}

func (r *ctxKeyring) getBindSessions(ctx context.Context) []extension.SessionBind {
	return *ctx.Value(SessionsKey{}).(*[]extension.SessionBind)
}

// RemoveAll removes all identities.
func (r *legacyKeyring) RemoveAll() error {
	return r.k.RemoveAll(r.dummyCtx)
}
func (r *ctxKeyring) RemoveAll(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.locked {
		return errLocked
	}

	r.keys = nil
	return nil
}

// removeLocked does the actual key removal. The caller must already be holding the
// keyring mutex.
func (r *ctxKeyring) removeLocked(want []byte) error {
	found := false
	for i := 0; i < len(r.keys); {
		if bytes.Equal(r.keys[i].signer.PublicKey().Marshal(), want) {
			found = true
			r.keys[i] = r.keys[len(r.keys)-1]
			r.keys = r.keys[:len(r.keys)-1]
			continue
		} else {
			i++
		}
	}

	if !found {
		return errors.New("agent: key not found")
	}
	return nil
}

// Remove removes all identities with the given public key.
func (r *legacyKeyring) Remove(key ssh.PublicKey) error {
	return r.k.Remove(r.dummyCtx, key)
}
func (r *ctxKeyring) Remove(ctx context.Context, key ssh.PublicKey) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.locked {
		return errLocked
	}

	return r.removeLocked(key.Marshal())
}

// Lock locks the agent. Sign and Remove will fail, and List will return an empty list.
func (r *legacyKeyring) Lock(passphrase []byte) error {
	return r.k.Lock(r.dummyCtx, passphrase)
}
func (r *ctxKeyring) Lock(ctx context.Context, passphrase []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.locked {
		return errLocked
	}

	r.locked = true
	r.passphrase = passphrase
	return nil
}

// Unlock undoes the effect of Lock
func (r *legacyKeyring) Unlock(passphrase []byte) error {
	return r.k.Unlock(r.dummyCtx, passphrase)
}
func (r *ctxKeyring) Unlock(ctx context.Context, passphrase []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.locked {
		return errors.New("agent: not locked")
	}
	if 1 != subtle.ConstantTimeCompare(passphrase, r.passphrase) {
		return fmt.Errorf("agent: incorrect passphrase")
	}

	r.locked = false
	r.passphrase = nil
	return nil
}

// expireKeysLocked removes expired keys from the keyring. If a key was added
// with a lifetimesecs contraint and seconds >= lifetimesecs seconds have
// elapsed, it is removed. The caller *must* be holding the keyring mutex.
func (r *ctxKeyring) expireKeysLocked() {
	for _, k := range r.keys {
		if k.expire != nil && time.Now().After(*k.expire) {
			r.removeLocked(k.signer.PublicKey().Marshal())
		}
	}
}

// List returns the identities known to the agent.
func (r *legacyKeyring) List() ([]*Key, error) {
	return r.k.List(r.dummyCtx)
}
func (r *ctxKeyring) List(ctx context.Context) ([]*Key, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.locked {
		// section 2.7: locked agents return empty.
		return nil, nil
	}

	r.expireKeysLocked()
	var ids []*Key
	for _, k := range r.keys {
		pub := k.signer.PublicKey()

		//if len(k.destinationConstraints) > 0 && len(r.sessions) > 0 {
		//	if !extension.IdentityPermitted(k.destinationConstraints, r.sessions, "") {
		//		continue
		//	}
		//}

		ids = append(ids, &Key{
			Format:  pub.Type(),
			Blob:    pub.Marshal(),
			Comment: k.comment,
		})
	}
	return ids, nil
}

// Insert adds a private key to the keyring. If a certificate
// is given, that certificate is added as public key. Note that
// any constraints given are ignored.
func (r *legacyKeyring) Add(key AddedKey) error {
	return r.k.Add(r.dummyCtx, key)
}
func (r *ctxKeyring) Add(ctx context.Context, key AddedKey) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.locked {
		return errLocked
	}
	signer, err := ssh.NewSignerFromKey(key.PrivateKey)

	if err != nil {
		return err
	}

	if cert := key.Certificate; cert != nil {
		signer, err = ssh.NewCertSigner(cert, signer)
		if err != nil {
			return err
		}
	}

	p := privKey{
		signer:  signer,
		comment: key.Comment,
	}

	if key.LifetimeSecs > 0 {
		t := time.Now().Add(time.Duration(key.LifetimeSecs) * time.Second)
		p.expire = &t
	}

	// take care of "official" extensions
	for _, constraint := range key.ConstraintExtensions {
		switch constraint.ExtensionName {
		case extension.EXT_NAME_RESTRICT_DESTINATION_00:
			if ctx.Value(SessionsKey{}) == nil {
				return errLegacyAgent
			} else {
				fmt.Println("Taking care of", extension.EXT_NAME_RESTRICT_DESTINATION_00)

				if p.destinationConstraints != nil {
					return fmt.Errorf("agent: multiple %s extensions", extension.EXT_NAME_RESTRICT_DESTINATION_00)
				}
				p.destinationConstraints, err = extension.ParseRestrictDestinations(constraint.ExtensionDetails)
				if err != nil {
					return err
				}
			}
		}
	}

	r.keys = append(r.keys, p)

	return nil
}

// Sign returns a signature for the data.
func (r *legacyKeyring) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return r.k.Sign(r.dummyCtx, key, data, 0)
}
func (r *legacyKeyring) SignWithFlags(key ssh.PublicKey, data []byte, flags SignatureFlags) (*ssh.Signature, error) {
	return r.k.Sign(r.dummyCtx, key, data, flags)
}
func (r *ctxKeyring) Sign(ctx context.Context, key ssh.PublicKey, data []byte, flags SignatureFlags) (*ssh.Signature, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.locked {
		return nil, errLocked
	}

	r.expireKeysLocked()
	wanted := key.Marshal()
	for _, k := range r.keys {
		if bytes.Equal(k.signer.PublicKey().Marshal(), wanted) {

			if k.destinationConstraints != nil {
				sessions := r.getBindSessions(ctx)
				if len(sessions) == 0 {
					return nil, fmt.Errorf("agent: refusing use of destination-constrained key to sign on unbound connection")
				}
				lastSessionBind := sessions[len(sessions)-1]

				fmt.Println("#######")
				signData, err := extension.ParseSignData(data, wanted)
				if err != nil {
					return nil, fmt.Errorf("agent: unable to parse sign data")
				}
				fmt.Printf("signData: %+v\n", signData)
				fmt.Printf("lastSessionBind: %+v\n", lastSessionBind)
				fmt.Printf("destinationConstraints: %+v\n", k.destinationConstraints)
				fmt.Println("#######")

				/*if err := ssh.Unmarshal(data, &signData); err != nil {
					fmt.Printf("%+v\n", signData)
					fmt.Println(err.Error())
					//return nil, err
					//refusing use of destination-constrained key to sign an unidentified signature
				}*/

				if !extension.IdentityPermitted(k.destinationConstraints, sessions, signData.User) {
					return nil, fmt.Errorf("agent: destination contrained")
				}

				/*
				 * Ensure that the session ID is the most recent one
				 * registered on the socket - it should have been bound by
				 * ssh immediately before userauth.
				 */
				if !lastSessionBind.Matching(signData.Session) {
					return nil, fmt.Errorf("agent: invalid session id")
				}

				/*
				 * Ensure that the hostkey embedded in the signature matches
				 * the one most recently bound to the socket. An exception is
				 * made for the initial forwarding hop.
				 */
				if len(sessions) > 1 && len(signData.HostKey) == 0 {
					return nil, fmt.Errorf("agent: refusing use of destination-constrained key: no hostkey recorded in signature for forwarded connection")
				}
				if len(signData.HostKey) > 0 && !bytes.Equal(signData.HostKey, lastSessionBind.Hostkey) {
					fmt.Println("refusing use of destination-constrained key: mismatch between hostkey in request and most recently bound session")
					//return nil, fmt.Errorf("agent: refusing use of destination-constrained key: mismatch between hostkey in request and most recently bound session")
				}
			}

			if flags == 0 {
				return k.signer.Sign(rand.Reader, data)
			} else {
				if algorithmSigner, ok := k.signer.(ssh.AlgorithmSigner); !ok {
					return nil, fmt.Errorf("agent: signature does not support non-default signature algorithm: %T", k.signer)
				} else {
					var algorithm string
					switch flags {
					case SignatureFlagRsaSha256:
						algorithm = ssh.KeyAlgoRSASHA256
					case SignatureFlagRsaSha512:
						algorithm = ssh.KeyAlgoRSASHA512
					default:
						return nil, fmt.Errorf("agent: unsupported signature flags: %d", flags)
					}
					return algorithmSigner.SignWithAlgorithm(rand.Reader, data, algorithm)
				}
			}
		}
	}
	return nil, errors.New("not found")
}

// Signers returns signers for all the known keys.
func (r *legacyKeyring) Signers() ([]ssh.Signer, error) {
	return r.k.Signers(r.dummyCtx)
}
func (r *ctxKeyring) Signers(ctx context.Context) ([]ssh.Signer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.locked {
		return nil, errLocked
	}

	r.expireKeysLocked()
	s := make([]ssh.Signer, 0, len(r.keys))
	for _, k := range r.keys {
		s = append(s, k.signer)
	}
	return s, nil
}

// The keyring implements only some extensions
func (r *legacyKeyring) Extension(extensionType string, contents []byte) ([]byte, error) {
	return r.k.Extension(r.dummyCtx, extensionType, contents)
}

func (r *ctxKeyring) Extension(ctx context.Context, extensionType string, contents []byte) ([]byte, error) {

	r.mu.Lock()
	defer r.mu.Unlock()

	switch extensionType {
	case extension.EXT_NAME_SESSION_BIND:
		if ctx.Value(SessionsKey{}) == nil {
			return nil, errLegacyAgent
		}
		sessionBind, err := extension.ParseSessionBind(contents)
		if err != nil {
			return nil, err
		}
		r.addBindSession(ctx, sessionBind)
		return []byte{agentSuccess}, nil
	}
	fmt.Println("Extension not implemented:", extensionType)
	return nil, ErrExtensionUnsupported
}
