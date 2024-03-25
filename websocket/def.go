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
	"unsafe"

	log "github.com/ChrIgiSta/go-utils/logger"
	"github.com/gorilla/websocket"
)

type Message struct {
	MessageType int
	Data        []byte
	ClientId    int
}

type Events interface {
	OnReceive(msg Message)
	OnDisconnect(id int)
	OnConnect(id int)
	OnFailure(exited bool, err error)
}

func getIdFromConn(conn *websocket.Conn) int {
	return int(uintptr(unsafe.Pointer(conn)))
}

type EventType int

const (
	Connect         EventType = 1
	Disconnect      EventType = 0
	Failure         EventType = -1
	FailureWithExit EventType = -2
)

type Event struct {
	Err  error
	Type EventType
	Id   int
}

type EventsToChannel struct {
	messageChannel chan<- Message
	eventChannel   chan<- Event
}

func NewEventsToChannel(messageChannel chan<- Message,
	eventChannel chan<- Event) *EventsToChannel {
	return &EventsToChannel{
		messageChannel: messageChannel,
		eventChannel:   eventChannel,
	}
}

func (t *EventsToChannel) OnReceive(msg Message) {
	log.Debug("Evnt2Channel", "onReceive: %v", msg)
	if t.messageChannel != nil {
		t.messageChannel <- msg
	} else {
		log.Error("Evnt2Channel", "message channel is nil")
	}
}
func (t *EventsToChannel) OnDisconnect(id int) {
	log.Debug("Evnt2Channel", "onDisconnect: %v", id)
	if t.eventChannel != nil {
		t.eventChannel <- Event{
			Err:  nil,
			Type: Disconnect,
			Id:   id,
		}
	} else {
		log.Error("Evnt2Channel", "event channel is nil")
	}
}
func (t *EventsToChannel) OnConnect(id int) {
	log.Debug("Evnt2Channel", "onConnect: %v", id)
	if t.eventChannel != nil {
		t.eventChannel <- Event{
			Err:  nil,
			Type: Connect,
			Id:   id,
		}
	} else {
		log.Error("Evnt2Channel", "event channel is nil")
	}
}
func (t *EventsToChannel) OnFailure(exited bool, err error) {
	log.Debug("Evnt2Channel", "onFailure: %v", err)

	fType := Failure
	if exited {
		fType = FailureWithExit
	}

	if t.eventChannel != nil {
		t.eventChannel <- Event{
			Err:  err,
			Type: fType,
			Id:   -1,
		}
	} else {
		log.Error("Evnt2Channel", "event channel is nil")
	}
}
