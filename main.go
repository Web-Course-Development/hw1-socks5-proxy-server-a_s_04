package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	socks5Version = 0x05

	methodNoAuth       = 0x00
	methodUsernamePass = 0x02
	methodNoAcceptable = 0xff

	authVersion = 0x01

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03

	repSucceeded             = 0x00
	repGeneralFailure        = 0x01
	repHostUnreachable       = 0x04
	repConnectionRefused     = 0x05
	repCommandNotSupported   = 0x07
	repAddressTypeNotSupport = 0x08
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

func handleConnection(client net.Conn) {
	defer client.Close()

	if err := negotiateAuth(client); err != nil {
		log.Printf("authentication failed: %v", err)
		return
	}

	target, err := handleConnect(client)
	if err != nil {
		log.Printf("connect request failed: %v", err)
		return
	}
	defer target.Close()

	relay(client, target)
}

func negotiateAuth(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	if header[0] != socks5Version {
		return fmt.Errorf("invalid socks version: %d", header[0])
	}

	nMethods := int(header[1])
	if nMethods == 0 {
		conn.Write([]byte{socks5Version, methodNoAcceptable})
		return fmt.Errorf("no authentication methods provided")
	}

	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	proxyUser := os.Getenv("PROXY_USER")
	proxyPass := os.Getenv("PROXY_PASS")
	authRequired := proxyUser != ""

	if authRequired {
		if !hasMethod(methods, methodUsernamePass) {
			conn.Write([]byte{socks5Version, methodNoAcceptable})
			return fmt.Errorf("username/password auth required but not offered")
		}

		if _, err := conn.Write([]byte{socks5Version, methodUsernamePass}); err != nil {
			return err
		}

		return authenticateUsernamePassword(conn, proxyUser, proxyPass)
	}

	if hasMethod(methods, methodNoAuth) {
		_, err := conn.Write([]byte{socks5Version, methodNoAuth})
		return err
	}

	conn.Write([]byte{socks5Version, methodNoAcceptable})
	return fmt.Errorf("no acceptable authentication method")
}

func hasMethod(methods []byte, wanted byte) bool {
	for _, method := range methods {
		if method == wanted {
			return true
		}
	}
	return false
}

func authenticateUsernamePassword(conn net.Conn, expectedUser string, expectedPass string) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	if header[0] != authVersion {
		conn.Write([]byte{authVersion, 0x01})
		return fmt.Errorf("invalid auth version: %d", header[0])
	}

	usernameLength := int(header[1])
	usernameBytes := make([]byte, usernameLength)
	if _, err := io.ReadFull(conn, usernameBytes); err != nil {
		return err
	}

	passwordLengthBuffer := make([]byte, 1)
	if _, err := io.ReadFull(conn, passwordLengthBuffer); err != nil {
		return err
	}

	passwordLength := int(passwordLengthBuffer[0])
	passwordBytes := make([]byte, passwordLength)
	if _, err := io.ReadFull(conn, passwordBytes); err != nil {
		return err
	}

	username := string(usernameBytes)
	password := string(passwordBytes)

	if username != expectedUser || password != expectedPass {
		conn.Write([]byte{authVersion, 0x01})
		return fmt.Errorf("invalid username or password")
	}

	_, err := conn.Write([]byte{authVersion, 0x00})
	return err
}

func handleConnect(conn net.Conn) (net.Conn, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	version := header[0]
	command := header[1]
	reserved := header[2]
	addressType := header[3]

	if version != socks5Version {
		sendSocksReply(conn, repGeneralFailure)
		return nil, fmt.Errorf("invalid request version: %d", version)
	}

	if reserved != 0x00 {
		sendSocksReply(conn, repGeneralFailure)
		return nil, fmt.Errorf("invalid reserved byte: %d", reserved)
	}

	if command != cmdConnect {
		sendSocksReply(conn, repCommandNotSupported)
		return nil, fmt.Errorf("unsupported command: %d", command)
	}

	host, err := readAddress(conn, addressType)
	if err != nil {
		sendSocksReply(conn, repAddressTypeNotSupport)
		return nil, err
	}

	portBuffer := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuffer); err != nil {
		sendSocksReply(conn, repGeneralFailure)
		return nil, err
	}

	port := binary.BigEndian.Uint16(portBuffer)
	targetAddress := net.JoinHostPort(host, strconv.Itoa(int(port)))

	target, err := net.Dial("tcp", targetAddress)
	if err != nil {
		sendSocksReply(conn, dialErrorToReply(err))
		return nil, err
	}

	if err := sendSocksReply(conn, repSucceeded); err != nil {
		target.Close()
		return nil, err
	}

	return target, nil
}

func readAddress(conn net.Conn, addressType byte) (string, error) {
	switch addressType {
	case atypIPv4:
		buffer := make([]byte, 4)
		if _, err := io.ReadFull(conn, buffer); err != nil {
			return "", err
		}

		return net.IP(buffer).String(), nil

	case atypDomain:
		lengthBuffer := make([]byte, 1)
		if _, err := io.ReadFull(conn, lengthBuffer); err != nil {
			return "", err
		}

		domainLength := int(lengthBuffer[0])
		if domainLength == 0 {
			return "", fmt.Errorf("empty domain name")
		}

		domainBuffer := make([]byte, domainLength)
		if _, err := io.ReadFull(conn, domainBuffer); err != nil {
			return "", err
		}

		return string(domainBuffer), nil

	default:
		return "", fmt.Errorf("unsupported address type: %d", addressType)
	}
}

func sendSocksReply(conn net.Conn, reply byte) error {
	// VER REP RSV ATYP BND.ADDR BND.PORT
	// For this homework, returning 0.0.0.0:0 is acceptable.
	response := []byte{
		socks5Version,
		reply,
		0x00,
		atypIPv4,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}

	_, err := conn.Write(response)
	return err
}

func dialErrorToReply(err error) byte {
	if err == nil {
		return repSucceeded
	}

	message := strings.ToLower(err.Error())

	if strings.Contains(message, "connection refused") {
		return repConnectionRefused
	}

	if strings.Contains(message, "no such host") ||
		strings.Contains(message, "host is down") ||
		strings.Contains(message, "network is unreachable") ||
		strings.Contains(message, "i/o timeout") {
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
		_ = tcpConn.CloseWrite()
		return
	}

	_ = conn.Close()
}
