// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package dubbo

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/apache/dubbo-go-hessian2"
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/packetbeat/procs"
	"github.com/elastic/beats/v7/packetbeat/protos"
	conf "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
	"time"
)

type dubboPrivateData struct {
	data [2]*dubboStream
}

type dubboStream struct {
	tcptuple *common.TCPTuple

	data []byte

	parseOffset int

	message *dubboMessage
}

type dubboMessage struct {
	ts        time.Time
	isRequest bool
	tcpTuple  common.TCPTuple
	// 魔数（2 字节）
	magic uint16
	// 标志（1 字节）
	flag string
	// 状态（1 字节）
	status string
	// 请求 ID（8 字节，大端序）
	requestID uint64
	// 数据长度（4 字节，大端序）
	dataLen uint32
	// 数据（不定长）
	dubboData string
}

type dubboPlugin struct {
	// config
	ports        []int
	sendRequest  bool
	sendResponse bool

	transactionTimeout time.Duration

	results protos.Reporter
	watcher *procs.ProcessesWatcher
}

func init() {
	protos.Register("dubbo", New)
}

func New(
	testMode bool,
	results protos.Reporter,
	watcher *procs.ProcessesWatcher,
	cfg *conf.C,
) (protos.Plugin, error) {
	p := &dubboPlugin{}
	config := defaultConfig
	if !testMode {
		if err := cfg.Unpack(&config); err != nil {
			return nil, err
		}
	}

	if err := p.init(results, watcher, &config); err != nil {
		return nil, err
	}
	return p, nil
}

func (dubbo *dubboPlugin) setFromConfig(config *dubboConfig) {
	dubbo.ports = config.Ports
	dubbo.sendRequest = config.SendRequest
	dubbo.sendResponse = config.SendResponse
	dubbo.transactionTimeout = config.TransactionTimeout
}

func (dubbo *dubboPlugin) GetPorts() []int {
	return dubbo.ports
}

func (dubbo *dubboPlugin) init(results protos.Reporter, watcher *procs.ProcessesWatcher, config *dubboConfig) error {
	dubbo.setFromConfig(config)
	dubbo.results = results
	dubbo.watcher = watcher

	return nil
}

// 超时时间
func (dubbo *dubboPlugin) ConnectionTimeout() time.Duration {
	return dubbo.transactionTimeout
}

func dubboMessageParser(s *dubboStream) (bool, bool) {

	// 读取Dubbo魔数（0xda, 0xbb）
	magic := s.readBytes(2)
	if !bytes.Equal(magic, []byte{0xda, 0xbb}) {
		return false, false
	}

	// 读取Dubbo消息类型（请求或响应）
	messageType := s.readByte()
	isRequest := messageType == 0

	// 读取请求/响应ID
	requestID := s.readUint64()

	// 如果是请求，解析服务名和方法名
	if isRequest {
		serviceName := s.readString()
		methodName := s.readString()
		// 解析请求参数
		parameters := s.readBytes(len(s.data))
		// 打印解析结果
		fmt.Printf("Request ID: %d\nService Name: %s\nMethod Name: %s\nParameters: %s\n", requestID, serviceName, methodName, parameters)
		return true, false // 表示成功解析请求

	} else {
		// 如果是响应，解析响应结果
		// 响应状态，通常为0表示成功
		status := s.readByte()
		result := s.readBytes(len(s.data))
		fmt.Printf("Request ID: %d\nStatus: %d\nResult: %s\n", requestID, status, result)
		return false, true // 表示成功解析请求
	}

	return false, false
}

// 以下是辅助函数，用于读取不同类型的数据
func (s *dubboStream) readByte() byte {
	b := s.data[0]
	s.data = s.data[1:]
	return b
}

func (s *dubboStream) readUint64() uint64 {
	data := s.readBytes(8)
	return binary.BigEndian.Uint64(data)
}

func (s *dubboStream) readString() string {
	length := int(s.readUint32())
	return string(s.readBytes(length))
}

func (s *dubboStream) readUint32() uint32 {
	data := s.readBytes(4)
	return binary.BigEndian.Uint32(data)
}

func (stream *dubboStream) prepareForNewMessage() {
	stream.data = stream.data[stream.parseOffset:]
	stream.parseOffset = 0
	stream.message = nil
}

// 重置解析状态
func (s *dubboStream) reset() {
	s.parseOffset = 0
	s.message = nil
}

// 处理空包丢包
func (dubbo *dubboPlugin) GapInStream(tcptuple *common.TCPTuple, dir uint8,
	nbytes int, private protos.ProtocolData) (priv protos.ProtocolData, drop bool,
) {

	if private == nil {
		return private, false
	}

	return private, true
}

// 处理TCP断开连接
func (dubbo *dubboPlugin) ReceivedFin(tcptuple *common.TCPTuple, dir uint8,
	private protos.ProtocolData,
) protos.ProtocolData {
	logp.Info("dubbo", "stream closed...")
	return private
}

func (s *dubboStream) readBytes(length int) []byte {
	bytes := s.data[:length]
	s.data = s.data[length:]
	return bytes
}

// 解析Packet
func (dubbo *dubboPlugin) Parse(pkt *protos.Packet, tcptuple *common.TCPTuple,
	dir uint8, private protos.ProtocolData,
) protos.ProtocolData {
	// 解析 Dubbo 数据包的逻辑
	// 在这里处理 Dubbo 协议的解析逻辑
	fmt.Println("解析 Dubbo 数据包:", pkt.Payload)
	if pkt == nil || pkt.Payload == nil {
		return private
	}

	//获取header。16个字节长度
	dubboHeader := pkt.Payload[:16] // Extracting first 16 bytes as Dubbo header
	//判断是否为dubbo协议
	if isDubbo(dubboHeader) {

		//获取body的长度
		ok, length := bodyLength(dubboHeader)
		if ok {

			//获取body的字节数组内容
			ok, body := bodyByte(pkt.Payload, length)
			if ok {

				//判断是请求还是响应
				if isRequest(dubboHeader) {
					fmt.Println("请求======》")
					doReq(body)

				} else {
					fmt.Println("《======响应")
					doRes(body)
				}
			}
		}
	}
	return private
}

func doReq(body []byte) {
	bodyUse := body
	for i := 0; i < 6; i++ {
		bodyUse = useByte(body)
		if i == 0 {
			fmt.Println("req dubbo version is :", string(bodyUse))
		} else if i == 1 {
			fmt.Println("req dubbo service is :", string(bodyUse))
		} else if i == 2 {
			fmt.Println("req dubbo service version is :", string(bodyUse))
		} else if i == 3 {
			fmt.Println("req dubbo method is :", string(bodyUse))
		} else if i == 4 {
			fmt.Println("req dubbo method param type is :", string(bodyUse))
		} else if i == 5 {
			fmt.Println("req dubbo method param is :", string(bodyUse))
		}
		//移除已经使用的字节
		if len(bodyUse) > 0 {
			body = body[len(bodyUse):]
		}
	}
}

func doRes(body []byte) {
	bodyUse := body
	for i := 0; i < 2; i++ {
		bodyUse = useByte(body)
		if i == 0 {
			fmt.Println("res type is :", string(bodyUse[0]))
		} else if i == 1 {
			fmt.Println("res content is :", string(bodyUse))
		}
		//移除已经使用的字节
		if len(bodyUse) > 0 {
			body = body[len(bodyUse):]
		}
	}
}

func useByte(body []byte) []byte {
	if len(body) > 0 {
		decodedObject, err := hessian.NewDecoder(body).Decode()
		if err == nil {
			encoder := hessian.NewEncoder()
			encoder.Encode(decodedObject)
			return encoder.Buffer()
		} else {
			fmt.Println("err:", err)
		}
	}
	return nil
}

// Called when the parser has identified a full message.
func (dubbo *dubboPlugin) messageComplete(tcptuple *common.TCPTuple, dir uint8, stream *dubboStream) {
	// and reset message
	stream.prepareForNewMessage()
}

func (dubbo *dubboPlugin) isServerPort(port uint16) bool {
	for _, sPort := range dubbo.ports {
		if uint16(sPort) == port {
			return true
		}
	}
	return false
}

// 判断是否为dubbo协议（以魔数判断）
func isDubbo(dubboHeader []byte) bool {
	if len(dubboHeader) < 2 {
		fmt.Println("dubboHeader length is less than 2 bytes, unable to read Dubbo magic number")
		return false
	}
	// 读取前2个字节作为 Dubbo 魔数
	dubboMagic := dubboHeader[:2]
	// 判断 Dubbo 魔数是否匹配
	if !bytes.Equal(dubboMagic, []byte{0xda, 0xbb}) {
		fmt.Printf("Dubbo magic number not found. Got: %x\n", dubboMagic)
		return false
	}
	return true
}

// 判断是否为请求/响应
func isRequest(dubboHeader []byte) bool {
	if len(dubboHeader) < 2 {
		fmt.Println("dubboHeader length is less than 3 bytes, unable to read Dubbo req/res flag")
		return false
	}
	// Extracting the 3 byte of Dubbo header
	thirdByte := dubboHeader[2]
	reqResFlag := (thirdByte & 0x80) >> 7
	//请求=1,响应=0
	return reqResFlag == 1
}

// 获取body的长度
func bodyLength(dubboHeader []byte) (bool, int) {
	if len(dubboHeader) < 16 {
		fmt.Println("dubboHeader length is less than 16 bytes, unable to read body length")
		return false, 0
	}
	messageLength := int(binary.BigEndian.Uint32(dubboHeader[12:16]))
	return true, messageLength
}

func bodyByte(payload []byte, length int) (bool, []byte) {
	if len(payload) < 16+length {
		fmt.Println("unable to read body")
		return false, nil
	}
	data := payload[16 : 16+length]
	return true, data
}
