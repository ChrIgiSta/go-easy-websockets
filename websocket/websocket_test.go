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
	"math/big"
	"testing"
	"time"

	ccrypt "github.com/ChrIgiSta/go-utils/crypto"
)

func TestWebsocketNoTls(t *testing.T) {
	var (
		testClient *EventsToChannel
		testServer *EventsToChannel

		sRxCh   chan Message = make(chan Message, 10)
		cRxCh   chan Message = make(chan Message, 10)
		sEvntCh chan Event   = make(chan Event, 10)
		cEvntCh chan Event   = make(chan Event, 10)
	)

	testClient = NewEventsToChannel(cRxCh, cEvntCh)
	testServer = NewEventsToChannel(sRxCh, sEvntCh)

	client := NewClient(false, testClient)
	server := NewServer("ws://localhost:33221/testPath", testServer)

	server.SetAuthHeader(&AuthHeader{
		HeaderRequired: map[string]string{
			"Token": "12345",
		},
		ValueHashAlgo: HashAlgoNone,
	})

	go func() { _ = server.ListenAndServe() }()

	time.Sleep(2 * time.Second)

	go func() {
		_ = client.ConnectAndServe("ws://localhost:33221/testPath", map[string]string{
			"Token": "12345",
		})
	}()

	time.Sleep(1 * time.Second)

	evnt := <-sEvntCh
	if evnt.Type == Connect {
		t.Logf("client <%d> @ server connected", evnt.Id)
	} else {
		t.Error("no connected event received @server")
	}

	evnt = <-cEvntCh
	if evnt.Type == Connect {
		t.Logf("client <%d> to server connected", evnt.Id)
	} else {
		t.Error("no connected event received @client")
	}

	server.Broadcast(&Message{
		MessageType: 1,
		Data:        []byte("Hello Client"),
	})

	msg := <-cRxCh
	if string(msg.Data) != "Hello Client" {
		t.Error("wrong msg server->client: ", string(msg.Data))
	}

	err := client.SendTxt([]byte("Hello Server"))
	if err != nil {
		t.Error("send client to server: ", err)
	}

	msg = <-sRxCh
	if string(msg.Data) != "Hello Server" {
		t.Error("wrong msg client->server: ", string(msg.Data))
	}

	err = client.Disconnect()
	if err != nil {
		t.Error(err)
	}

	time.Sleep(1 * time.Second)
	server.Close()
}

func TestWebsocketTls(t *testing.T) {
	var (
		testClient *EventsToChannel
		testServer *EventsToChannel

		sRxCh   chan Message = make(chan Message, 10)
		cRxCh   chan Message = make(chan Message, 10)
		sEvntCh chan Event   = make(chan Event, 10)
		cEvntCh chan Event   = make(chan Event, 10)
	)

	testClient = NewEventsToChannel(cRxCh, cEvntCh)
	testServer = NewEventsToChannel(sRxCh, sEvntCh)

	cert, key, err := ccrypt.CreateSelfsignedX509Certificate(big.NewInt(123),
		100, ccrypt.KeyLength4096Bit,
		ccrypt.CertificateSubject{
			Organisation: "MyOrg",
			Country:      "CH",
			Province:     "Irgendwo",
			Locality:     "Im Nirgendwo",
			OrgUnit:      "Undefined",
			CommonName:   "localhost",
		})

	if err != nil {
		t.Error(err)
	}

	client := NewClient(true, testClient)
	server := NewServer("wss://localhost:33221/testPath", testServer)

	server.SetupTls(cert, key)

	client.AddRootCa(cert)
	client.DisableCommonNameCheck() // Doesn't work ...

	go func() { _ = server.ListenAndServe() }()

	time.Sleep(2 * time.Second) // wait for server

	go func() {
		_ = client.ConnectAndServe("wss://localhost:33221/testPath", nil)
	}()

	evnt := <-sEvntCh
	if evnt.Type == Connect {
		t.Logf("client <%d> connected", evnt.Id)
	} else {
		t.Error("no connected event received")
	}

	err = client.Disconnect()
	if err != nil {
		t.Error(err)
	}

	time.Sleep(1 * time.Second)
	server.Close()
}
