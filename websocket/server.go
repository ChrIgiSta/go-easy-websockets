/**
 * Copyright © 2024, Staufi Tech - Switzerland
 * All rights reserved.
 *
 *   ________________________   ___ _     ________________  _  ____
 *  / _____  _  ____________/  / __|_|   /_______________  | | ___/
 * ( (____ _| |_ _____ _   _ _| |__ _      | |_____  ____| |_|_
 *  \____ (_   _|____ | | | (_   __) |     | | ___ |/ ___)  _  \
 *  _____) )| |_/ ___ | |_| | | |  | |     | | ____( (___| | | |
 * (______/  \__)_____|____/  |_|  |_|     |_|_____)\____)_| |_|
 *
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

package websocket

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"hash"
	"net/http"
	"sync"

	"github.com/ChrIgiSta/go-easy-websockets/utils"
	"github.com/ChrIgiSta/go-utils/containers"
	log "github.com/ChrIgiSta/go-utils/logger"
	"github.com/gorilla/websocket"
)

const LogRegioWsServer = "ws server"

type HashAlgo int

const (
	HashAlgoNone   = 0
	HashAlgoMD5    = 1
	HashAlgoSHA256 = 2
)

type AuthHeader struct {
	HeaderRequired map[string]string
	ValueHashAlgo  HashAlgo
}

func NewAuthHeader(headerKey string, headerValue string, valueHashAlgo HashAlgo) *AuthHeader {
	return &AuthHeader{
		HeaderRequired: map[string]string{
			headerKey: headerValue,
		},
		ValueHashAlgo: valueHashAlgo,
	}
}

type Server struct {
	wg           sync.WaitGroup
	address      string
	path         string
	clientPool   *containers.List
	tls          bool
	certificate  []byte
	privateKey   []byte
	server       *http.Server
	eventHandler Events
	authHeader   *AuthHeader
}

func NewServer(url string,
	eventHander Events) *Server {

	u, err := utils.StringToUrl(url)
	if err != nil {
		log.Error(LogRegioWsServer, "invalid url: %v", err)
		return nil
	}

	server := Server{
		wg:           sync.WaitGroup{},
		address:      u.Host,
		path:         u.Path,
		eventHandler: eventHander,
		clientPool:   containers.NewList(),
		tls:          false,
	}

	return &server
}

func (s *Server) SetupTls(certificate []byte, privateKey []byte) {
	s.certificate = certificate
	s.privateKey = privateKey
	s.tls = true
}

func (s *Server) SetAuthHeader(authHeader *AuthHeader) {
	s.authHeader = authHeader
}

func (s *Server) validateHash(value string, hashValue string, algo HashAlgo) bool {

	var hasher hash.Hash

	switch algo {
	case HashAlgoNone:
		return value == hashValue
	case HashAlgoMD5:
		hasher = md5.New()
	case HashAlgoSHA256:
		hasher = sha256.New()
	default:
		return false
	}
	hashedValue := hasher.Sum([]byte(value))

	return string(hashedValue) == hashValue
}

func (s *Server) clientHandler(w http.ResponseWriter, r *http.Request) {

	if s.authHeader != nil {
		for key, value := range s.authHeader.HeaderRequired {
			valueGot := r.Header.Get(key)
			if !s.validateHash(valueGot, value, s.authHeader.ValueHashAlgo) {
				log.Debug(LogRegioWsServer, "not authorized")
				w.WriteHeader(http.StatusUnauthorized)
				// not authorized
				return
			}
		}
	}

	upgrader := websocket.Upgrader{}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Info(LogRegioWsServer, "upgrade conn: %v", err)
		return
	}

	clientId := getIdFromConn(conn)
	s.clientPool.AddOrUpdate(clientId, conn)

	log.Debug(LogRegioWsServer, "new client<%d> connected: %s",
		clientId, conn.RemoteAddr().String())
	defer log.Debug(LogRegioWsServer, "client <%d> disconnected", clientId)

	defer s.clientPool.Delete(clientId)
	defer s.eventHandler.OnDisconnect(clientId)
	s.eventHandler.OnConnect(clientId)

	for {
		messageType, payload, err := conn.ReadMessage()

		if err != nil {
			log.Info(LogRegioWsServer,
				"read from client: %v. exit client handler", err)
			return
		}

		log.Debug(LogRegioWsServer, "rx type <%d>: %s",
			messageType, payload)

		s.eventHandler.OnReceive(Message{
			MessageType: messageType,
			Data:        payload,
			ClientId:    clientId,
		})
	}
}

func (s *Server) ListenAndServe() (err error) {

	var serverCert tls.Certificate

	s.wg.Add(1)
	defer log.Debug(LogRegioWsServer, "listener exited")
	defer s.wg.Done()

	mux := http.ServeMux{}
	mux.HandleFunc(s.path, s.clientHandler)

	s.server = &http.Server{
		Addr:    s.address,
		Handler: &mux,
	}

	if s.tls {
		serverCert, err = tls.X509KeyPair(
			s.certificate,
			s.privateKey)
		if err != nil {
			err = fmt.Errorf("load x509 keypair: %v", err)
			s.eventHandler.OnFailure(true, err)
			return
		}
		tlsConfig := tls.Config{
			Certificates: []tls.Certificate{serverCert},
		}
		s.server.TLSConfig = &tlsConfig
	}

	log.Info(LogRegioWsServer, "ws server start listening @ %v%v",
		s.address, s.path)

	if !s.tls {
		err = s.server.ListenAndServe()
	} else {
		err = s.server.ListenAndServeTLS("", "")
	}

	s.eventHandler.OnFailure(true, fmt.Errorf("exited: %v", err))

	return err
}

func (s *Server) Broadcast(message *Message) {
	var err error

	clientIds := s.clientPool.GetIds()
	for _, id := range clientIds {
		_, conn := s.clientPool.Get(id)
		if conn == nil {
			log.Warn(LogRegioWsServer, "no connection for id %v", id)
			s.clientPool.Delete(id)
			continue
		}
		client := conn.(*websocket.Conn)
		err = client.WriteMessage(message.MessageType,
			message.Data)
		if err != nil {
			s.eventHandler.OnFailure(false,
				fmt.Errorf("send to client <%v>: %v", id, err))

			log.Error(LogRegioWsServer, "send<%v>: %v", id, err)
		}
	}
	if len(clientIds) < 1 {
		log.Debug(LogRegioWsServer, "no clients connected")
	}
}

func (s *Server) Send(clientId int, message *Message) error {
	_, conn := s.clientPool.Get(clientId)
	if conn == nil {
		return errors.New("no valid client")
	}
	client := conn.(*websocket.Conn)
	return client.WriteMessage(message.MessageType,
		message.Data)
}

func (s *Server) Close() (err error) {
	defer s.wg.Wait()
	err = s.server.Close()
	return
}
