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

package main

import (
	"bufio"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/ChrIgiSta/go-easy-websockets/utils"
	"github.com/ChrIgiSta/go-easy-websockets/websocket"

	ccrypt "github.com/ChrIgiSta/go-utils/crypto"
)

func main() {

	var (
		serverAddress          string
		server, skipValidation bool
		err                    error
		cert, key              string
	)

	serverAddress, server, skipValidation, cert, key, err = parseArgs()
	if err != nil || serverAddress == "" {
		fmt.Println(err)
		help()
		os.Exit(-1)
	}

	if _, err = utils.StringToUrl(serverAddress); err != nil {
		fmt.Println(err)
		help()
		os.Exit(-1)
	}

	if server {
		err = serve(serverAddress, []byte(cert), []byte(key))
	} else {
		err = connect(serverAddress, skipValidation)
	}

	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	os.Exit(0)
}

func serve(address string, cert []byte, key []byte) (err error) {

	var (
		messageCh chan websocket.Message
		eventCh   chan websocket.Event

		done bool
	)

	messageCh = make(chan websocket.Message, 1024)
	eventCh = make(chan websocket.Event, 1024)

	eventToCh := websocket.NewEventsToChannel(messageCh, eventCh)
	server := websocket.NewServer(address, eventToCh)

	tls := utils.TlsScheme(address)
	if tls {
		if len(cert) == 0 || len(key) == 0 {
			fmt.Println("WARNING: using tls without providing a certificate. generate a self signed one.")
			cert, key, err = ccrypt.CreateSelfsignedX509Certificate(big.NewInt(123),
				100, ccrypt.KeyLength4096Bit,
				ccrypt.CertificateSubject{
					Organisation: "Easy Websockets",
					Country:      "CH",
					Province:     "Zurich",
					Locality:     "Zurich",
					CommonName:   address,
				})

			if err != nil {
				return
			}
		}
		server.SetupTls(cert, key)
	}

	go func() {
		err = server.ListenAndServe()
		if err != nil {
			fmt.Println(err)
		}
	}()

	go handleMessagesAndEvents(&done, messageCh, eventCh)

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() && !done {
		txt := scanner.Text()
		switch txt {
		case "exit":
			server.Close()
			done = true
		default:
			server.Broadcast(&websocket.Message{
				MessageType: 1,
				Data:        []byte(txt),
			})
		}
	}

	return
}

func connect(serverAddress string, skipValidation bool) (err error) {

	var (
		messageCh chan websocket.Message
		eventCh   chan websocket.Event

		done bool
	)

	messageCh = make(chan websocket.Message, 1024)
	eventCh = make(chan websocket.Event, 1024)

	eventToCh := websocket.NewEventsToChannel(messageCh, eventCh)
	client := websocket.NewClient(skipValidation, eventToCh)

	go func() {
		err = client.ConnectAndServe(serverAddress, nil)
		if err != nil {
			fmt.Println(err)
		}
	}()

	go handleMessagesAndEvents(&done, messageCh, eventCh)

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() && !done {
		txt := scanner.Text()
		switch txt {
		case "exit":
			_ = client.Disconnect()
			done = true
		default:
			err = client.SendTxt([]byte(txt))
			if err != nil {
				fmt.Println(err)
			}
		}
	}

	return
}

func handleMessagesAndEvents(done *bool,
	messageCh <-chan websocket.Message,
	eventCh <-chan websocket.Event) {

	for !*done {
		select {
		case msg := <-messageCh:
			fmt.Printf("rx from client: %s\r\n", string(msg.Data))
		case evnt := <-eventCh:
			switch evnt.Type {
			case websocket.Connect:
				fmt.Println("connected")
			case websocket.Disconnect:
				fmt.Println("disconnected")
			case websocket.Failure:
				fmt.Println("failure ", evnt.Err)
			}
		}
	}
}

func parseArgs() (serverAddress string, server, skipVerify bool, certPath, keyPath string, err error) {
	var ignore bool

	args := os.Args[1:]

	if len(args) < 1 {
		return "", false, false, "", "", errors.New("missing args")
	}

	for idx, arg := range args {
		if ignore {
			ignore = false
			continue
		}

		switch arg {

		case "-l", "--listen":
			server = true
			if len(args) < idx+2 {
				return "", false, false, "", "",
					errors.New("missing parameter for listen")
			}
			ignore = true
			serverAddress = args[idx+1]

		case "-c", "--connect":
			server = false
			if len(args) < idx+2 {
				return "", false, false, "", "",
					errors.New("missing parameter for connect")
			}
			ignore = true
			serverAddress = args[idx+1]

		case "-k", "--skip-verify":
			skipVerify = true

		case "--cert":
			if len(args) < idx+2 {
				return "", false, false, "", "",
					errors.New("missing parameter for certificate")
			}
			ignore = true
			certPath = args[idx+1]

		case "--key":
			if len(args) < idx+2 {
				return "", false, false, "", "",
					errors.New("missing parameter for private key")
			}
			ignore = true
			keyPath = args[idx+1]
		}
	}

	return
}

func help() {
	fmt.Println("GoLang Easy Websockets by ChrIgiSta")
	fmt.Println(`
      ________________________   ___ _     ________________  _  ____
     / _____  _  ____________/  / __|_|   /_______________  | | ___/
    ( (____ _| |_ _____ _   _ _| |__ _      | |_____  ____| |_|_
     \____ (_   _|____ | | | (_   __) |     | | ___ |/ ___)  _  \
     _____) )| |_/ ___ | |_| | | |  | |     | | ____( (___| | | |
    (______/  \__)_____|____/  |_|  |_|     |_|_____)\____)_| |_|

	                                  Copyright © 2024, Staufi Tech`)
	fmt.Println("How To Use:")
	fmt.Println(`
	Server:

	Flags         	Parameters
	-l, --listen: 	<ws://localhost:12345/path>`)

	fmt.Println(`
	Client:

	Flags         	Parameters
	-c, --connect: 	<ws://10.100.23.1:12345/path>`)

	fmt.Println(`
	Optional:

	Flags         		Parameters
	--cert: 			</path/to/cert.pem>
	--key: 				</path/to/key.pem>
	-k, --skip-verify	skip validation of servers certificate
	
Exiting:
	just typing 'exit'`)

}
