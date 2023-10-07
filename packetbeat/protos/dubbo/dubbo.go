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
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/packetbeat/procs"
	"github.com/elastic/beats/v7/packetbeat/protos"
	"github.com/elastic/beats/v7/packetbeat/protos/tcp"
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

func (s *dubboStream) readBytes(length int) []byte {
	bytes := s.data[:length]
	s.data = s.data[length:]
	return bytes
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

// 解析Packet
func (dubbo *dubboPlugin) Parse(pkt *protos.Packet, tcptuple *common.TCPTuple,
	dir uint8, private protos.ProtocolData,
) protos.ProtocolData {
	// 解析 Dubbo 数据包的逻辑
	// 在这里处理 Dubbo 协议的解析逻辑
	fmt.Println("解析 Dubbo 数据包:", pkt.Payload)

	priv := dubboPrivateData{}
	if private != nil {
		var ok bool
		priv, ok = private.(dubboPrivateData)
		if !ok {
			priv = dubboPrivateData{}
		}
	}

	if priv.data[dir] == nil {
		//客户端到服务器端的请求
		priv.data[dir] = &dubboStream{
			data:    pkt.Payload,
			message: &dubboMessage{ts: pkt.Ts},
		}
	} else {
		// concatenate bytes
		priv.data[dir].data = append(priv.data[dir].data, pkt.Payload...)
		if len(priv.data[dir].data) > tcp.TCPMaxDataInStream {
			logp.Debug("dubbo", "Stream data too large, dropping TCP stream")
			priv.data[dir] = nil
			return priv
		}
	}

	stream := priv.data[dir]
	for len(stream.data) > 0 {
		if stream.message == nil {
			stream.message = &dubboMessage{ts: pkt.Ts}
		}

		ok, complete := dubboMessageParser(priv.data[dir])
		if !ok {
			// drop this tcp stream. Will retry parsing with the next
			// segment in it
			priv.data[dir] = nil
			logp.Debug("dubbo", "Ignore DUBBO message. Drop tcp stream. Try parsing with the next segment")
			return priv
		}

		if complete {
			dubbo.messageComplete(tcptuple, dir, stream)
		} else {
			// wait for more data
			break
		}
	}
	return priv
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
