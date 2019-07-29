// Package iscsinl acts as an initiator for bootstrapping an iscsi connection
// Partial implementation of RFC3720 login and NETLINK_ISCSI, just enough to
// get a connection going.
package iscsinl

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Login constants
const (
	ISCSI_OP_LOGIN     = 0x03
	ISCSI_OP_LOGIN_RSP = 0x23
	ISCSI_OP_IMMEDIATE = 0x40

	ISCSI_VERSION = 0x00

	ISCSI_FLAG_LOGIN_TRANSIT  = 0x80
	ISCSI_FLAG_LOGIN_CONTINUE = 0x40
)

// IscsiLoginStage corresponds to iSCSI login stage
type IscsiLoginStage uint8

// Login stages
const (
	ISCSI_SECURITY_NEGOTIATION_STAGE IscsiLoginStage = 0
	ISCSI_OP_PARMS_NEGOTIATION_STAGE                 = 1
	ISCSI_FULL_FEATURE_PHASE                         = 3
)

func hton24(buf *[3]byte, num int) {
	buf[0] = uint8(((num) >> 16) & 0xFF)
	buf[1] = uint8(((num) >> 8) & 0xFF)
	buf[2] = uint8((num) & 0xFF)
}

func ntoh24(buf [3]byte) uint {
	return (uint(buf[0]) << 16) | (uint(buf[1]) << 8) | uint(buf[2])
}

func hton48(buf *[6]byte, num int) {
	buf[0] = uint8(((num) >> 40) & 0xFF)
	buf[1] = uint8(((num) >> 32) & 0xFF)
	buf[2] = uint8(((num) >> 24) & 0xFF)
	buf[3] = uint8(((num) >> 16) & 0xFF)
	buf[4] = uint8(((num) >> 8) & 0xFF)
	buf[5] = uint8((num) & 0xFF)
}

// LoginHdr is the header for ISCSI_OP_LOGIN
// See: RFC3720 10.12.
type LoginHdr struct {
	Opcode     uint8
	Flags      uint8
	MaxVersion uint8
	MinVersion uint8
	HLength    uint8
	DLength    [3]uint8
	Isid       [6]uint8
	Tsih       uint16
	Itt        uint32
	Cid        uint16
	Rsvd3      uint16
	CmdSN      uint32
	ExpStatSN  uint32
	Rsvd5      [16]uint8
}

// LoginRspHdr is the header for ISCSI_OP_LOGIN_RSP
// See: RFC3720 10.13.
type LoginRspHdr struct {
	Opcode        uint8
	Flags         uint8
	MaxVersion    uint8
	ActiveVersion uint8
	HLength       uint8
	DLength       [3]uint8
	Isid          [6]uint8
	Tsih          uint16
	Itt           uint32
	Rsvd3         uint32
	StatSN        uint32
	ExpCmdSN      uint32
	MaxCmdSN      uint32
	StatusClass   uint8
	StatusDetail  uint8
	Rsvd5         [10]uint8
}

// IscsiLoginPdu is an iSCSI Login Request PDU
type IscsiLoginPdu struct {
	Header       LoginHdr
	TextSegments bytes.Buffer
}

// HeaderLen gives the length of the PDU header
func (l *IscsiLoginPdu) HeaderLen() uint32 {
	return uint32(binary.Size(l.Header))
}

// DataLen gives the length of all data segements for this PDU
func (l *IscsiLoginPdu) DataLen() uint32 {
	return uint32(l.TextSegments.Len())
}

// Serialize to network order bytes
func (l *IscsiLoginPdu) Serialize() []byte {
	var buf bytes.Buffer

	hton24(&l.Header.DLength, int(l.DataLen()))
	binary.Write(&buf, binary.LittleEndian, l.Header)
	buf.Write(l.TextSegments.Bytes())
	return buf.Bytes()
}

// AddParam the key=value string to the login payload and adds null terminator
func (l *IscsiLoginPdu) AddParam(keyvalue string) {
	l.TextSegments.WriteString(keyvalue)
	l.TextSegments.WriteByte(0)
}

// ReReadPartitionTable opens the given file and reads partition table from it
func ReReadPartitionTable(devname string) error {
	f, err := os.OpenFile(devname, os.O_RDWR, 0)
	if err != nil {
		return err
	}

	_, err = unix.IoctlGetInt(int(f.Fd()), unix.BLKRRPART)
	return err
}

// IscsiTargetSession represents an iSCSI session and a single connection to a target
type IscsiTargetSession struct {
	addr   string
	volume string
	cid    uint32
	hostID uint32
	sid    uint32

	// Update this on login response
	tsih           uint16
	expCmdSN       uint32
	maxCmdSN       uint32
	expStatSN      uint32
	currStage      IscsiLoginStage
	maxRecvDlength int
	maxXmitDlength int
	headerDigest   string
	dataDigest     string

	// Seconds to wait for heartbeat response before declaring the connection dead
	pingTimeout int32
	// Seconds to wait on an idle connection before sending a heartbeat
	recvTimeout int32

	conn    *net.TCPConn
	netlink *IscsiIpcConn
}

// NewSession constructs an IscsiTargetSession
func NewSession(addr string, volumeName string, netlink *IscsiIpcConn) *IscsiTargetSession {
	return &IscsiTargetSession{
		addr:           addr,
		volume:         volumeName,
		netlink:        netlink,
		maxRecvDlength: 1048576,
		maxXmitDlength: 1048576,
		headerDigest:   "CRC32C",
		dataDigest:     "CRC32C",
		pingTimeout:    60,
		recvTimeout:    60,
	}
}

// Connect creates a kernel iSCSI session and connection, connects to the
// target, and binds the connection to the kernel session.
func (s *IscsiTargetSession) Connect() error {
	var err error
	s.sid, s.hostID, err = s.netlink.CreateSession()
	if err != nil {
		return err
	}

	s.cid, err = s.netlink.CreateConnection(s.sid)
	if err != nil {
		return err
	}

	resolvedAddr, err := net.ResolveTCPAddr("tcp", s.addr)
	if err != nil {
		return err
	}

	s.conn, err = net.DialTCP("tcp", nil, resolvedAddr)
	if err != nil {
		return err
	}

	file, err := s.conn.File()
	defer file.Close()
	fd := file.Fd()

	return s.netlink.BindConnection(s.sid, s.cid, int(fd))
}

// Start starts the kernel iSCSI session. Call this after successfully
// logging in and setting all desired parameters.
func (s *IscsiTargetSession) Start() error {
	return s.netlink.StartConnection(s.sid, s.cid)
}

// TearDown stops and destroys the connection & session
// in case of partially created session, stopping connections/destroying
// connections won't work, so try it all
func (s *IscsiTargetSession) TearDown() error {
	sConnErr := s.netlink.StopConnection(s.sid, s.cid)

	dConnErr := s.netlink.DestroyConnection(s.sid, s.cid)

	if err := s.netlink.DestroySession(s.sid); err != nil {
		return fmt.Errorf("failure to destroy session DestroySession:%v DestroyConnection:%v StopConnection:%v", err, dConnErr, sConnErr)
	}
	return nil
}

func bool2str(pred bool) string {
	if pred {
		return "1"
	}
	return "0"
}

// SetParams sets some desired parameters for the kernel session
func (s *IscsiTargetSession) SetParams() error {

	params := []struct {
		p IscsiParam
		v string
	}{
		{ISCSI_PARAM_TARGET_NAME, s.volume},
		{ISCSI_PARAM_INITIATOR_NAME, "iscsi_startup.go"},
		{ISCSI_PARAM_MAX_RECV_DLENGTH, fmt.Sprintf("%d", s.maxRecvDlength)},
		{ISCSI_PARAM_MAX_XMIT_DLENGTH, fmt.Sprintf("%d", s.maxXmitDlength)},
		{ISCSI_PARAM_HDRDGST_EN, bool2str(s.headerDigest == "CRC32C")},
		{ISCSI_PARAM_DATADGST_EN, bool2str(s.dataDigest == "CRC32C")},
		{ISCSI_PARAM_PING_TMO, fmt.Sprintf("%d", s.pingTimeout)},
		{ISCSI_PARAM_RECV_TMO, fmt.Sprintf("%d", s.recvTimeout)},
	}

	for _, pp := range params {
		log.Printf("Setting param %v to %v", pp.p, pp.v)
		if err := s.netlink.SetParam(s.sid, s.cid, pp.p, pp.v); err != nil {
			return err
		}
	}
	return nil
}

// Scan triggers a scsi host scan so the kernel creates a block device for the
// newly attached session, then waits for the block device to be created and
// returns the device name.
func (s *IscsiTargetSession) Scan() (string, error) {

	file, err := os.OpenFile(fmt.Sprintf("/sys/class/scsi_host/host%d/scan", s.hostID), os.O_WRONLY, 0)
	if err != nil {
		return "", err
	}
	if _, err := file.WriteString("- - 1"); err != nil {
		file.Close()
		return "", err
	}
	// If Close() fails this likely indicates a write failure.
	if err := file.Close(); err != nil {
		return "", err
	}

	var matches []string
	for {
		log.Printf("Waiting for device...")
		time.Sleep(30 * time.Millisecond)
		matches, err = filepath.Glob(fmt.Sprintf(
			"/sys/class/iscsi_session/session%d/device/target*/*/block/*/uevent", s.sid))

		if err != nil {
			return "", err
		}

		if len(matches) > 1 {
			return "", fmt.Errorf("unexpected number of targets attached to session: %d", len(matches))
		} else if len(matches) == 1 {
			break
		}
	}

	contents, err := ioutil.ReadFile(matches[0])
	if err != nil {
		return "", err
	}

	for _, kv := range strings.Split(string(contents), "\n") {
		splitkv := strings.Split(kv, "=")
		if splitkv[0] == "DEVNAME" {
			return splitkv[1], nil
		}
	}
	return "", errors.New("could not find DEVNAME")
}

// processOperationalParam assigns params returned from the target. Errors if
// we cannot continue with negotiation.
func (s *IscsiTargetSession) processOperationalParam(keyvalue string) error {
	split := strings.Split(keyvalue, "=")
	if len(split) != 2 {
		return fmt.Errorf("invalid format for operational param \"%v\"", keyvalue)
	}
	key, value := split[0], split[1]

	if value == "Reject" {
		return fmt.Errorf("target rejected parameter %q", key)
	}

	switch key {
	case "MaxRecvDataSegmentLength":
		length, err := strconv.ParseInt(value, 10, 32)
		if err != nil {
			return err
		}
		s.maxXmitDlength = int(length)
	case "HeaderDigest":
		s.headerDigest = value
	case "DataDigest":
		s.dataDigest = value
	default:
		log.Printf("Ignoring unknown param \"%v\"", keyvalue)
	}
	return nil
}

// processOperationalParams processes all parameters in a login response
func (s *IscsiTargetSession) processOperationalParams(data []byte) error {
	params := strings.Split(string(data), "\x00")
	// Annoyingly, strings.Split will always have an empty string at the end
	// An empty string in the middle of params suggests we have an otherwise
	// malformed request, since we shouldn't expect double nul bytes
	params = params[0 : len(params)-1]
	for _, param := range params {
		if err := s.processOperationalParam(param); err != nil {
			return err
		}
	}
	return nil
}

func (s *IscsiTargetSession) processLoginResponse(response []byte) error {
	var loginRespPdu LoginRspHdr
	reader := bytes.NewReader(response)
	if err := binary.Read(reader, binary.LittleEndian, &loginRespPdu); err != nil {
		return err
	}
	if loginRespPdu.Opcode != ISCSI_OP_LOGIN_RSP {
		return fmt.Errorf("unexpected response pdu opcode %d", loginRespPdu.Opcode)
	}

	if loginRespPdu.StatusClass != 0 {
		return fmt.Errorf("error in login response %d %d", loginRespPdu.StatusClass, loginRespPdu.StatusDetail)
	}

	s.maxCmdSN = loginRespPdu.MaxCmdSN
	s.expCmdSN = loginRespPdu.ExpCmdSN
	s.tsih = loginRespPdu.Tsih
	s.expStatSN = loginRespPdu.StatSN + 1
	if (loginRespPdu.Flags & ISCSI_FLAG_LOGIN_TRANSIT) != 0 {
		s.currStage = IscsiLoginStage(loginRespPdu.Flags & 0x03)
	}

	// dLength generally != the length of the rest of the netlink buffer
	dLength := int(ntoh24(loginRespPdu.DLength))
	theRest := make([]byte, dLength)
	read, err := reader.Read(theRest)
	if err != nil {
		return err
	}
	if read != dLength {
		return errors.New("unexpected EOF reading PDU data")
	}
	return s.processOperationalParams(theRest)
}

// Login - RFC iSCSI login
// https://www.ietf.org/rfc/rfc3720.txt
// For now "negotiates" no auth security.
func (s *IscsiTargetSession) Login(hostname string) error {
	log.Println("Starting login...")

	for s.currStage != ISCSI_OP_PARMS_NEGOTIATION_STAGE {
		loginReq := IscsiLoginPdu{
			Header: LoginHdr{
				Opcode:     ISCSI_OP_LOGIN | ISCSI_OP_IMMEDIATE,
				MaxVersion: ISCSI_VERSION,
				MinVersion: ISCSI_VERSION,
				ExpStatSN:  s.expStatSN,
				Tsih:       s.tsih,
				Flags:      uint8((s.currStage << 2) | ISCSI_OP_PARMS_NEGOTIATION_STAGE | ISCSI_FLAG_LOGIN_TRANSIT),
			},
		}
		hton48(&loginReq.Header.Isid, int(s.sid))
		loginReq.AddParam("AuthMethod=None")
		loginReq.AddParam(fmt.Sprintf("InitiatorName=%s:iscsi_startup.go", hostname))
		loginReq.AddParam(fmt.Sprintf("TargetName=%s", s.volume))

		if err := s.netlink.SendPDU(s.sid, s.cid, &loginReq); err != nil {
			return fmt.Errorf("sendPDU: %v", err)
		}

		response, err := s.netlink.RecvPDU(s.sid, s.cid)
		if err != nil {
			return fmt.Errorf("recvpdu: %v", err)
		}
		if err = s.processLoginResponse(response); err != nil {
			return err
		}
	}

	for s.currStage != ISCSI_FULL_FEATURE_PHASE {
		loginReq := IscsiLoginPdu{
			Header: LoginHdr{
				Opcode:     ISCSI_OP_LOGIN | ISCSI_OP_IMMEDIATE,
				MaxVersion: ISCSI_VERSION,
				MinVersion: ISCSI_VERSION,
				ExpStatSN:  s.expStatSN,
				Tsih:       s.tsih,
				Flags:      uint8((s.currStage << 2) | ISCSI_FULL_FEATURE_PHASE | ISCSI_FLAG_LOGIN_TRANSIT),
			},
		}
		hton48(&loginReq.Header.Isid, int(s.sid))
		loginReq.AddParam(fmt.Sprintf("InitiatorName=%s:iscsi_startup.go", hostname))
		loginReq.AddParam(fmt.Sprintf("TargetName=%s", s.volume))
		loginReq.AddParam("SessionType=Normal")
		loginReq.AddParam(fmt.Sprintf("MaxRecvDataSegmentLength=%d", s.maxRecvDlength))
		loginReq.AddParam(fmt.Sprintf("HeaderDigest=%v", s.headerDigest))
		loginReq.AddParam(fmt.Sprintf("DataDigest=%v", s.dataDigest))

		if err := s.netlink.SendPDU(s.sid, s.cid, &loginReq); err != nil {
			return fmt.Errorf("sendpdu2: %v", err)
		}

		response, err := s.netlink.RecvPDU(s.sid, s.cid)
		if err != nil {
			return fmt.Errorf("recvpdu2: %v", err)
		}
		if err = s.processLoginResponse(response); err != nil {
			return err
		}
	}
	return nil

}

// MountIscsi connects to the given iscsi target and mounts it, returning the
// device name on success
func MountIscsi(address string, volume string) (string, error) {
	netlink, err := ConnectNetlink()
	if err != nil {
		return "", fmt.Errorf("netlink: %v", err)
	}

	// We use local hostname to identify ourselves to the target
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}

	session := NewSession(address, volume, netlink)
	if err = session.Connect(); err != nil {
		return "", fmt.Errorf("connect: %v", err)
	}

	if err := session.Login(hostname); err != nil {
		return "", fmt.Errorf("login: %v", err)
	}

	if err := session.SetParams(); err != nil {
		return "", fmt.Errorf("params: %v", err)
	}

	if err := session.Start(); err != nil {
		return "", fmt.Errorf("start: %v", err)
	}

	devname, err := session.Scan()
	if err != nil {
		return "", err
	}

	if err := ReReadPartitionTable("/dev/" + devname); err != nil {
		return "", err
	}
	return devname, nil
}

// TearDownIscsi tears down the specified session
func TearDownIscsi(sid uint32, cid uint32) error {
	netlink, err := ConnectNetlink()
	if err != nil {
		return err
	}
	session := IscsiTargetSession{sid: sid, cid: cid, netlink: netlink}

	return session.TearDown()
}
