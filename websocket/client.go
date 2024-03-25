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
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"sync"

	"github.com/ChrIgiSta/go-easy-websockets/utils"
	ccrypt "github.com/ChrIgiSta/go-utils/crypto"
	log "github.com/ChrIgiSta/go-utils/logger"
	"github.com/gorilla/websocket"
)

const LogRegioWsClient = "websocket client"

type Client struct {
	conn         *websocket.Conn
	eventHandler Events
	wg           sync.WaitGroup
	tlsConfig    tls.Config
	rootCAs      *x509.CertPool
	checker      *ccrypt.CertChecker
}

func NewClient(skipCertValidation bool, eventHandler Events) *Client {
	return &Client{
		eventHandler: eventHandler,
		wg:           sync.WaitGroup{},
		tlsConfig:    tls.Config{InsecureSkipVerify: skipCertValidation},
	}
}

func (c *Client) AddRootCa(rootCA []byte) {
	block, _ := pem.Decode(rootCA)
	if block == nil {
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Warn(LogRegioWsClient, "error adding ca: %v", err)
		return
	}
	if c.rootCAs == nil {
		c.rootCAs = x509.NewCertPool()
	}
	c.rootCAs.AddCert(cert)
}

func (c *Client) DisableCommonNameCheck() {
	c.checker = ccrypt.NewCustomCertChecker(c.rootCAs)
	c.tlsConfig.VerifyPeerCertificate = c.checker.X509CeckCertNoSAN
}

func (c *Client) ConnectAndServe(url string,
	header map[string]string) (err error) {

	c.wg.Add(1)
	defer c.wg.Done()

	defer log.Debug(LogRegioWsServer, "serve exited")

	u, err := utils.StringToUrl(url)
	if err != nil {
		return err
	}

	log.Debug(LogRegioWsClient, "connecting to %s", u.String())

	if utils.TlsScheme(u.Scheme) {
		websocket.DefaultDialer.TLSClientConfig = &c.tlsConfig
	}

	var dailResp *http.Response

	c.conn, dailResp, err = websocket.DefaultDialer.Dial(u.String(),
		utils.MapToHeader(header))
	if err != nil {
		var respBody []byte
		if dailResp != nil {
			respBody, _ = io.ReadAll(dailResp.Body)
		}
		log.Error(LogRegioWsClient, "dail<%v>: %v", err, string(respBody))
		return err
	}

	defer dailResp.Body.Close()
	defer c.conn.Close()

	id := getIdFromConn(c.conn)
	c.eventHandler.OnConnect(id)
	defer c.eventHandler.OnDisconnect(id)

	for {
		msgType, data, err := c.conn.ReadMessage()
		if err != nil {
			c.eventHandler.OnFailure(true, err)
			return err
		}
		c.eventHandler.OnReceive(Message{
			MessageType: msgType,
			Data:        data,
			ClientId:    id,
		})
	}
}

func (c *Client) Disconnect() (err error) {
	log.Debug(LogRegioWsClient, "interrupted")

	defer c.wg.Wait()

	if c.conn != nil {
		err = c.conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		c.conn.Close()
	}

	return
}

func (c *Client) SendTxt(message []byte) (err error) {
	return c.conn.WriteMessage(websocket.TextMessage, message)
}

func (c *Client) Send(message Message) (err error) {
	return c.conn.WriteMessage(message.MessageType, message.Data)
}
