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
	isClient    bool

	message *dubboMessage
}

type dubboMessage struct {
	ts        time.Time
	isRequest bool
	tcpTuple  common.TCPTuple
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
	dubbo.transactionTimeout = dubbo.TransactionTimeout
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

	return true, false
}

func parsePasvResponse(response string) (string, int, error) {
	// 解析响应中的IP和端口信息，通常位于括号中
	start := strings.Index(response, "(")
	end := strings.Index(response, ")")
	if start != -1 && end != -1 {
		ipPortInfo := response[start+1 : end]
		parts := strings.Split(ipPortInfo, ",")
		if len(parts) == 6 {
			ip := strings.Join(parts[:4], ".")
			port := (parseInt(parts[4]) << 8) + parseInt(parts[5])
			return ip, port, nil
		}
	}
	return "", 0, fmt.Errorf("Failed to parse PASV response")
}

// 辅助函数：将字符串转换为整数
func parseInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

// 建立数据连接并获取报文内容
func fetchData(ip string, port int) ([]byte, error) {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 读取数据
	data := make([]byte, 4096)
	n, err := conn.Read(data)
	if err != nil {
		return nil, err
	}
	return data[:n], nil
}

func (stream *dubboStream) prepareForNewMessage() {
	stream.data = stream.data[stream.parseOffset:]
	stream.parseOffset = 0
	stream.message = nil
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
	logp.Info(pkt.Payload)

	/*priv := dubboPrivateData{}
	if private != nil {
		var ok bool
		priv, ok = private.(dubboPrivateData)
		if !ok {
			priv = dubboPrivateData{}
		}
	}

	if priv.data[dir] == nil {
		dstPort := tcptuple.DstPort
		if dir == tcp.TCPDirectionReverse {
			dstPort = tcptuple.SrcPort
		}
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
	}*/
	return priv
}

// Called when the parser has identified a full message.
func (dubbo *dubboPlugin) messageComplete(tcptuple *common.TCPTuple, dir uint8, stream *dubboStream) {

	logp.Info("dubbo", "message completed...")

	// all ok, ship it
	msg := stream.data[stream.message.start:stream.message.end]

	// and reset message
	stream.prepareForNewMessage()
}
