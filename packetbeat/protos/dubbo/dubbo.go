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
	conf "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
	"strings"
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

	ok, remainingData := isDubbo(pkt.Payload)
	if ok {
		payload := string(remainingData)
		lines := strings.Split(payload, "\n")
		for i, line := range lines {
			fmt.Printf("Line %d: %s\n", i+1, line)
		}
	}
	// 解析 Dubbo 协议消息
	/*messageType, remainingData := parseMessageType(pkt.Payload)
	requestID, remainingData := parseRequestID(remainingData)
	serviceName, remainingData := parseServiceName(remainingData)
	methodName, remainingData := parseMethodName(remainingData)*/
	/*parameters, remainingData := parseParameters(remainingData)*/

	// 在这里你可以处理解析出来的 Dubbo 协议信息
	/*fmt.Printf("Message Type: %d\n", messageType)
	fmt.Printf("Request ID: %d\n", requestID)
	fmt.Printf("Service Name: %s\n", serviceName)
	fmt.Printf("Method Name: %s\n", methodName)*/
	/*	log.Printf("Parameters: %v\n", parameters)
	 */
	// 返回 private，可用于在不同数据包之间传递信息
	return private
	/*
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
		return priv*/
}

// 判断是否为dubbo协议（以魔数判断）
func isDubbo(payload []byte) (bool, []byte) {
	// 判断负载长度是否大于等于4个字节（Dubbo 魔数长度）
	if len(payload) < 2 {
		fmt.Println("Payload length is less than 2 bytes, unable to read Dubbo magic number")
		return false, payload
	}
	// 读取前四个字节作为 Dubbo 魔数
	dubboMagic := payload[:2]
	// 判断 Dubbo 魔数是否匹配
	if !bytes.Equal(dubboMagic, []byte{0xda, 0xbb}) {
		fmt.Printf("Dubbo magic number not found. Got: %x\n", dubboMagic)
		return false, payload
	}
	remainingData := payload[2:]
	return true, remainingData
}

// 解析 Dubbo 消息类型
func parseMessageType(payload []byte) (int, []byte) {
	if len(payload) < 2 {
		// 数据包长度不足以解析消息类型
		return 0, payload
	}

	// Dubbo 协议中，消息类型通常是一个16位的整数
	messageType := binary.BigEndian.Uint16(payload)
	remainingData := payload[2:]

	return int(messageType), remainingData
}

// 解析 Dubbo 请求ID
func parseRequestID(payload []byte) (int64, []byte) {
	if len(payload) < 8 {
		// 数据包长度不足以解析请求ID
		return 0, payload
	}

	// Dubbo 协议中，请求ID通常是一个64位的整数，使用大端字节序存储
	requestID := int64(binary.BigEndian.Uint64(payload[:8]))
	remainingData := payload[8:]

	return requestID, remainingData
}

// 解析 Dubbo 服务名
func parseServiceName(payload []byte) (string, []byte) {
	// 假设 Dubbo 协议的服务名以 0x2f 字节作为分隔符
	separator := byte(0x2f)

	// 查找第一个分隔符的位置
	separatorIndex := bytes.IndexByte(payload, separator)
	if separatorIndex == -1 {
		// 没有找到分隔符，无法解析服务名
		return "", payload
	}

	// 提取服务名部分
	serviceName := string(payload[:separatorIndex])
	remainingData := payload[separatorIndex+1:]

	return serviceName, remainingData
}

// 解析 Dubbo 方法名
func parseMethodName(payload []byte) (string, []byte) {
	// 假设 Dubbo 协议的方法名以 0x2e 字节作为分隔符
	separator := byte(0x2e)

	// 查找第一个分隔符的位置
	separatorIndex := bytes.IndexByte(payload, separator)
	if separatorIndex == -1 {
		// 没有找到分隔符，无法解析方法名
		return "", payload
	}

	// 提取方法名部分
	methodName := string(payload[:separatorIndex])
	remainingData := payload[separatorIndex+1:]

	return methodName, remainingData
}

// 解析 Dubbo 参数
func parseParameters(payload []byte) (map[string]interface{}, []byte) {
	parameters := make(map[string]interface{})

	// 解析参数的逻辑需要根据 Dubbo 协议规范和实际情况来实现
	// 这里演示解析字符串、整数和布尔值参数的示例

	for len(payload) > 0 {
		// 参数类型标志位
		paramType := payload[0]
		payload = payload[1:]

		switch paramType {
		case 'S':
			// 字符串参数
			strLen := binary.BigEndian.Uint16(payload[:2])
			payload = payload[2:]
			paramValue := string(payload[:strLen])
			payload = payload[strLen:]
			parameters["stringParam"] = paramValue
		case 'I':
			// 整数参数
			paramValue := int(binary.BigEndian.Uint32(payload[:4]))
			payload = payload[4:]
			parameters["intParam"] = paramValue
		case 'B':
			// 布尔值参数
			paramValue := payload[0] != 0
			payload = payload[1:]
			parameters["boolParam"] = paramValue
		default:
			// 未知参数类型，可以根据需求处理
			// 这里可以记录日志或进行其他处理
			// 或者根据 Dubbo 协议规范处理其他参数类型
		}
	}

	return parameters, payload
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
