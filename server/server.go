package main

import (
	"flag"
	"net"
	"log"
	"bufio"
	"io"
	"fmt"
	"strconv"
	"strings"
	"errors"
	"proxyGo/server/internal"
 	_ "proxyGo/server/daemon"
)

const netMask = 0xf

const (
	successed   byte   =  iota
	socksServerError
	connectionNotAllowed
	networkUnreachable
	hostUnreachable
	connectionRefused
	ttlExpired
	commandNotSupport
	addressTypeNotSupport
	ffUnassigned
)


var (
	username = "slowmoon"
	password = "9xa24dwsw"
)


type Server struct {
	Version byte
}

func (s *Server) ListenAndServer(protocol, addr string) error {
	listener, e := net.Listen(protocol, addr)
	logger.Println("successfully start server:", addr)

	if e!=nil {
		logger.Println("error listen to ", addr)
		return e
	}
	for {
		conn, i := listener.Accept()
		if i!=nil {
			logger.Println("accept error", i)
			continue
		}

		go func() {
			defer conn.Close()
			if err := s.handleConn(conn);err!=nil{
				if err == io.EOF {
				}else {
					log.Println(err)
				}
			}
		}()
	}
}

type Request struct {
	Version byte
	Command byte
	AddrType byte
	IP4Addr []byte
	Ip6Addr []byte
	Host []byte
	Port int
}

func (req *Request)String()string{
	return fmt.Sprintf("%d %d %d %c %c %c %d\n", req.Version, req.Command, req.AddrType, req.IP4Addr,req.Ip6Addr, req.Host, req.Port)
}

type Response struct {
   Version byte
   Code byte
   Fixed byte
   addrType byte
   Addr  []byte
   Port []byte
}

func (res *Response) String()string {
	return fmt.Sprintf("%d %d %d %d %c %c", res.Version, res.Code, res.Fixed, res.addrType, res.addrType, res.Port)
}

func (s *Server)writeResponse(resp *Response, conn net.Conn)(err error){

	 buf := []byte{s.Version, resp.Code, resp.Fixed, resp.addrType}
	 buf = append(buf, resp.Addr...)
	 buf = append(buf, resp.Port...)

	 _, err = conn.Write(buf)
	 return
}

func (s *Server)response(conn net.Conn, ip net.IP, port int)error{
	
	var addrType byte
	var addr []byte

	if ip.To4()!=nil {
		addrType = 0x01
		addr = ip.To4()
	}else if ip.To16() != nil {
		addrType = 0x04
		addr = ip.To16()
	}else {
		return s.error(conn, addressTypeNotSupport)
	}

	resp :=	&Response{
		Version:s.Version,
		Code: successed,
		Addr: addr,
		addrType: addrType,
		Port: []byte{byte(port>>8), byte(port & 0xff)},
	}

	return s.writeResponse(resp, conn)
}

func (s *Server)connect(con net.Conn, req *Request)(err error){
	var addr string

	if req.Host != nil {
		addrp, err := net.ResolveIPAddr("ip", string(req.Host))
		if err!=nil {
			return s.error(con, socksServerError)
		}
		addr = addrp.String()

	}else if req.IP4Addr != nil {
		 addr = net.IPv4(
		 	req.IP4Addr[0],
		 	req.IP4Addr[1],
		 	req.IP4Addr[2],
		 	req.IP4Addr[3],
		 ).String()
	}else if req.Ip6Addr !=nil{
		addr = net.ParseIP(string(req.Ip6Addr)).String()
	}else {
		return s.error(con, addressTypeNotSupport)
	}

	host := net.JoinHostPort(addr, strconv.Itoa(req.Port))
	conn, err := net.Dial("tcp", host)

	if err != nil {
		respCode := hostUnreachable
		if strings.Contains(err.Error(), "refused") {
           respCode = connectionRefused
		}else if strings.Contains(err.Error(), "network is unreachable") {
			respCode = networkUnreachable
		}
	  return s.error(con, respCode)
	}

	defer conn.Close()

	tcpAddr := conn.LocalAddr().(*net.TCPAddr)

	s.response(con, tcpAddr.IP, tcpAddr.Port)

	chanerrors := make(chan error, 2)

	go  s.proxy(conn, con, chanerrors)
	go  s.proxy(con, conn, chanerrors)

	err= <-chanerrors

	if err!=nil{
		return err
	}

	if err!=nil{
		return err
	}

	return
}


func (s *Server)proxy(dst io.WriteCloser, src io.ReadCloser, errors chan error)(err error){
	_, err = io.Copy(dst, src)
	if conn, ok := dst.(*net.TCPConn);ok{
		conn.CloseWrite()
	}
	errors <- err
	return err
}



func (s *Server)request(conn net.Conn, reader *bufio.Reader)(err error){
	req := &Request{}

	header := make([]byte, 4)
	_, err = reader.Read(header)  //0 版本  1 :command 2：保留字 3:地址类型 4：地址长度 5：变长
	if err!=nil {
		return err
	}
    req.Version = header[0]
    req.Command = header[1]
    req.AddrType = header[3]

    addrLen := 0

	switch req.AddrType & netMask {
	case 0x1:
		addrLen = 4
	case 0x4:
		addrLen = 16
	case 0x3:
		b, err := reader.ReadByte()
		if err!=nil{
			return s.error(conn, socksServerError)
		}
		addrLen = int(b)
	}
	portBytes := 2

	b := make([]byte, addrLen + portBytes)

	_, err = io.ReadFull(reader, b)

	if err!=nil {
		return s.error(conn, socksServerError)
	}

	switch req.AddrType & netMask {
	case 0x1:
		req.IP4Addr = b[:addrLen]
	case 0x4:
		req.Ip6Addr = b[:addrLen]
	case 0x3:
		req.Host = b[:addrLen]
	}
	rp := b[addrLen:addrLen+portBytes]
	req.Port = int(rp[0])<<8 + int(rp[1])

	logger.Printf("request %+v", req)
	switch req.Command {
	case 0x1:
		return s.connect(conn, req)
	default:
		return s.error(conn, commandNotSupport)
	}

	return
}

func (s *Server)error(con net.Conn, command byte)error{
	resp := &Response{
		Version:s.Version,
		addrType: 0x01,
		Addr:[]byte{0, 0, 0, 0},
		Port:[]byte{0, 0},
		Code:command,
	}
	return s.writeResponse(resp, con)

}



func (s *Server)handleConn(con net.Conn)(err error){
	reader := bufio.NewReader(con)
	b, err := reader.ReadByte()     //1，读取协议版本
	if err!=nil {
		log.Println(err)
		return err
	}
	if b != s.Version {
		return errors.New("protocol not supported")
	}

	authCnt, err := reader.ReadByte()   //2，读取协议种类数目
	if err!=nil {
		log.Println(err)
		return err
	}
	content := make([]byte, int(authCnt))

	if _, err := io.ReadFull(reader, content);err!=nil && err!=io.EOF{
		fmt.Println(err)
		return err
	}

	_, err = con.Write([]byte{s.Version, 0})      //4，返回无需继续认证

/*	_, err = con.Write([]byte{s.Version, 0x02})      //4，返回，需要用户名密码验证
	s.auth(con)              //开始验证
*/
    s.request(con, reader)

	return
}



type Auth struct {
	Version byte
	User string
	Password string
}

func (s *Server)authResp(con net.Conn, cmd byte)(err error){
	_, err = con.Write([]byte{0x01, cmd})
	return
}


func (s *Server)auth(con net.Conn)(err error){
	buf := make([]byte, 200)

	n, err := con.Read(buf)
	if err!=nil &&err!=io.EOF{
		logger.Println("user password authentication fail!")
		s.authResp(con, 0x01)
		return
	}
    fmt.Printf("%c", buf[:n])

	auth := &Auth{}
	index := 0
	auth.Version  = buf[index]
	index++
	userLength := int(buf[index])
	index++
	auth.User = string(buf[index:index+userLength])

	fmt.Println(auth.Version, auth.User)

	if username != auth.User  {    //验证用户名密码是否正确
	logger.Println("auth fail, username or password is not correct")
		return s.authResp(con, 0x01)
	}

	return s.authResp(con, 0x00)              //正确的话，通过验证
}


var logger internal.Debug

func main() {
	  var port int

	  flag.IntVar(&port, "p", 8080, "specify the port")
	  flag.BoolVar((*bool)(&logger), "debug", false, "specify the port")

	  flag.Parse()

	  s := &Server{Version:5}
	  s.ListenAndServer("tcp", ":"+strconv.Itoa(port))

}