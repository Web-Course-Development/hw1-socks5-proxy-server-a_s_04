package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"flag"
)

const (
	socksVersion = 0x05

	methodNoAuth   = 0x00
	methodUserPass = 0x02
	methodNoAccept = 0xFF

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03

	repSuccess              = 0x00
	repGeneralFailure       = 0x01
	repHostUnreachable      = 0x04
	repConnectionRefused    = 0x05
	repCommandNotSupported  = 0x07
	repAddressNotSupported  = 0x08
)

func main() {
	port := flag.Int("port", 1080, "port to listen on")
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on :%d", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	if err := negotiateAuth(conn); err != nil {
		log.Printf("auth negotiation failed: %v", err)
		return
	}

	target, err := handleConnect(conn)
	if err != nil {
		log.Printf("connect failed: %v", err)
		return
	}
	defer target.Close()

	relay(conn, target)
}

func negotiateAuth(conn net.Conn) error {
	header := make([]byte, 2)

	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	if header[0] != socksVersion {
		return fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	nMethods := int(header[1])
	methods := make([]byte, nMethods)

	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	requiredUser := os.Getenv("PROXY_USER")
	requiredPass := os.Getenv("PROXY_PASS")

	authRequired := requiredUser != ""

	if authRequired {
		if !containsMethod(methods, methodUserPass) {
			conn.Write([]byte{socksVersion, methodNoAccept})
			return fmt.Errorf("client does not support username/password auth")
		}

		if _, err := conn.Write([]byte{socksVersion, methodUserPass}); err != nil {
			return err
		}

		return authenticateUserPass(conn, requiredUser, requiredPass)
	}

	if containsMethod(methods, methodNoAuth) {
		_, err := conn.Write([]byte{socksVersion, methodNoAuth})
		return err
	}

	conn.Write([]byte{socksVersion, methodNoAccept})
	return fmt.Errorf("no acceptable authentication method")
}

func containsMethod(methods []byte, wanted byte) bool {
	for _, method := range methods {
		if method == wanted {
			return true
		}
	}
	return false
}

func authenticateUserPass(conn net.Conn, requiredUser string, requiredPass string) error {
	header := make([]byte, 2)

	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	// Important: username/password auth uses version 0x01, not 0x05.
	if header[0] != 0x01 {
		conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("invalid username/password auth version: %d", header[0])
	}

	userLen := int(header[1])
	userBytes := make([]byte, userLen)

	if _, err := io.ReadFull(conn, userBytes); err != nil {
		return err
	}

	passLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, passLenBuf); err != nil {
		return err
	}

	passLen := int(passLenBuf[0])
	passBytes := make([]byte, passLen)

	if _, err := io.ReadFull(conn, passBytes); err != nil {
		return err
	}

	username := string(userBytes)
	password := string(passBytes)

	if username != requiredUser || password != requiredPass {
		conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("invalid username or password")
	}

	_, err := conn.Write([]byte{0x01, 0x00})
	return err
}

func handleConnect(conn net.Conn) (net.Conn, error) {
	header := make([]byte, 4)

	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	version := header[0]
	command := header[1]
	// header[2] is RSV, must be 0x00.
	addressType := header[3]

	if version != socksVersion {
		sendReply(conn, repGeneralFailure)
		return nil, fmt.Errorf("invalid SOCKS version in request: %d", version)
	}

	if command != cmdConnect {
		sendReply(conn, repCommandNotSupported)
		return nil, fmt.Errorf("unsupported command: %d", command)
	}

	host, err := readAddress(conn, addressType)
	if err != nil {
		sendReply(conn, repAddressNotSupported)
		return nil, err
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		sendReply(conn, repGeneralFailure)
		return nil, err
	}

	port := binary.BigEndian.Uint16(portBuf)
	targetAddress := net.JoinHostPort(host, strconv.Itoa(int(port)))

	target, err := net.Dial("tcp", targetAddress)
	if err != nil {
		rep := mapDialErrorToReply(err)
		sendReply(conn, rep)
		return nil, err
	}

	if err := sendReply(conn, repSuccess); err != nil {
		target.Close()
		return nil, err
	}

	return target, nil
}

func readAddress(conn net.Conn, addressType byte) (string, error) {
	switch addressType {
	case atypIPv4:
		ipBuf := make([]byte, 4)

		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return "", err
		}

		return net.IP(ipBuf).String(), nil

	case atypDomain:
		lenBuf := make([]byte, 1)

		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", err
		}

		domainLen := int(lenBuf[0])
		domainBuf := make([]byte, domainLen)

		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return "", err
		}

		return string(domainBuf), nil

	default:
		return "", fmt.Errorf("unsupported address type: %d", addressType)
	}
}

func sendReply(conn net.Conn, reply byte) error {
	// Reply format:
	// VER REP RSV ATYP BND.ADDR BND.PORT
	// We return IPv4 0.0.0.0 and port 0.
	response := []byte{
		socksVersion,
		reply,
		0x00,
		atypIPv4,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}

	_, err := conn.Write(response)
	return err
}

func mapDialErrorToReply(err error) byte {
	if err == nil {
		return repSuccess
	}

	errText := strings.ToLower(err.Error())

	if strings.Contains(errText, "connection refused") {
		return repConnectionRefused
	}

	if strings.Contains(errText, "no such host") ||
		strings.Contains(errText, "host is down") ||
		strings.Contains(errText, "network is unreachable") {
		return repHostUnreachable
	}

	return repGeneralFailure
}

func relay(client net.Conn, target net.Conn) {
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(target, client)
		closeWrite(target)
		done <- struct{}{}
	}()

	go func() {
		io.Copy(client, target)
		closeWrite(client)
		done <- struct{}{}
	}()

	<-done
	<-done
}

func closeWrite(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.CloseWrite()
	}
}