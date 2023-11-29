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
	"github.com/elastic/beats/v7/packetbeat/pb"
	"github.com/elastic/beats/v7/packetbeat/procs"
	"github.com/elastic/beats/v7/packetbeat/protos"
	"github.com/elastic/beats/v7/packetbeat/protos/tcp"
	conf "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/monitoring"
	"reflect"
	"time"
)

type dubboPrivateData struct {
	data [2]*dubboStream
}

type dubboStream struct {
	tcptuple *common.TCPTuple

	data []byte

	message *dubboMessage
}

type dubboMessage struct {
	start        int
	end          int
	ts           time.Time
	isRequest    bool
	cmdlineTuple *common.ProcessTuple
	tcpTuple     common.TCPTuple
	reqId        int64
	needResp     bool
	direction    uint8
	data         []byte
	size         int
	notes        []string
}

type dubboTransaction struct {
	tuple          common.TCPTuple
	src            common.Endpoint
	dst            common.Endpoint
	ts             time.Time
	endTime        time.Time
	version        string
	service        string
	serviceVersion string
	method         string
	paramType      string
	bytesOut       uint64
	bytesIn        uint64
	notes          []string

	request  interface{}
	response interface{}
}

type dubboPlugin struct {
	// config
	ports []int

	sendRequest  bool
	sendResponse bool

	transactions       *common.Cache
	transactionTimeout time.Duration

	results protos.Reporter
	watcher *procs.ProcessesWatcher
}

var (
	unmatchedRequests  = monitoring.NewInt(nil, "dubbo.unmatched_requests")
	unmatchedResponses = monitoring.NewInt(nil, "dubbo.unmatched_responses")
)

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
func (dubbo *dubboPlugin) init(results protos.Reporter, watcher *procs.ProcessesWatcher, config *dubboConfig) error {
	dubbo.setFromConfig(config)
	dubbo.transactions = common.NewCache(dubbo.transactionTimeout, protos.DefaultTransactionHashSize)
	dubbo.transactions.StartJanitor(dubbo.transactionTimeout)
	dubbo.watcher = &procs.ProcessesWatcher{}
	dubbo.results = results
	dubbo.watcher = watcher
	return nil
}
func (dubbo *dubboPlugin) setFromConfig(config *dubboConfig) {
	dubbo.ports = config.Ports
	dubbo.sendRequest = config.SendRequest
	dubbo.sendResponse = config.SendResponse
	dubbo.transactionTimeout = config.TransactionTimeout
}
func (dubbo *dubboPlugin) getTransaction(k int64) *dubboTransaction {
	v := dubbo.transactions.Get(k)
	if v != nil {
		return v.(*dubboTransaction)
	}
	return nil
}
func (dubbo *dubboPlugin) GetPorts() []int {
	return dubbo.ports
}

func (stream *dubboStream) prepareForNewMessage() {
	stream.data = nil
	stream.message = nil
}

func (dubbo *dubboPlugin) messageComplete(tcptuple *common.TCPTuple, dir uint8, stream *dubboStream) {
	// all ok, go to next level
	stream.message.tcpTuple = *tcptuple
	stream.message.direction = dir
	stream.message.cmdlineTuple = dubbo.watcher.FindProcessesTupleTCP(tcptuple.IPPort())
	dubbo.handleDubbo(stream.message)
	// and reset message
	stream.prepareForNewMessage()
}

// 超时时间
func (dubbo *dubboPlugin) ConnectionTimeout() time.Duration {
	return dubbo.transactionTimeout
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
func (dubbo *dubboPlugin) handleDubbo(m *dubboMessage) {
	if m.isRequest {
		dubbo.receivedRequest(m)
	} else {
		dubbo.receivedResponse(m)
	}
}
func (dubbo *dubboPlugin) receivedRequest(msg *dubboMessage) {
	tuple := msg.tcpTuple

	trans := dubbo.getTransaction(msg.reqId)
	if trans != nil {
		logp.Debug("dubbo", "Two requests without response, assuming the old one is oneway")
		unmatchedRequests.Add(1)
	}

	trans = &dubboTransaction{
		tuple: tuple,
	}
	dubbo.transactions.Put(msg.reqId, trans)

	trans.ts = msg.ts
	trans.src, trans.dst = common.MakeEndpointPair(msg.tcpTuple.BaseTuple, msg.cmdlineTuple)
	if msg.direction == tcp.TCPDirectionReverse {
		trans.src, trans.dst = trans.dst, trans.src
	}

	doReq(msg.data, trans)
	trans.bytesIn = uint64(msg.size)
}

func (dubbo *dubboPlugin) receivedResponse(msg *dubboMessage) {
	trans := dubbo.getTransaction(msg.reqId)
	if trans == nil {
		logp.Debug("dubbo", "Response from unknown transaction. Ignoring: %v", msg.reqId)
		unmatchedResponses.Add(1)
		return
	}

	doRes(msg.data, trans)
	trans.bytesOut = uint64(msg.size)
	trans.endTime = msg.ts

	dubbo.publishTransaction(trans)
	dubbo.transactions.Delete(msg.reqId)

	logp.Debug("dubbo", "Dubbo transaction completed req ID is: %s", msg.reqId)
}

// 解析Packet
func (dubbo *dubboPlugin) Parse(pkt *protos.Packet, tcptuple *common.TCPTuple,
	dir uint8, private protos.ProtocolData,
) protos.ProtocolData {

	priv := dubboPrivateData{}
	if private != nil {
		var ok bool
		priv, ok = private.(dubboPrivateData)
		if !ok {
			priv = dubboPrivateData{}
		}
	}

	stream := priv.data[dir]
	if stream == nil {
		stream = &dubboStream{
			tcptuple: tcptuple,
			data:     pkt.Payload,
			message:  &dubboMessage{ts: pkt.Ts},
		}
		priv.data[dir] = stream
	} else {
		// concatenate bytes
		stream.data = append(stream.data, pkt.Payload...)
		if len(stream.data) > tcp.TCPMaxDataInStream {
			logp.Debug("dubbo", "Stream data too large, dropping TCP stream")
			priv.data[dir] = nil
			return priv
		}
	}

	if stream.message == nil {
		stream.message = &dubboMessage{ts: pkt.Ts}
	}

	ok, complete := dubbo.messageParser(priv.data[dir])
	if !ok {
		// drop this tcp stream. Will retry parsing with the next
		// segment in it
		priv.data[dir] = nil
		logp.Debug("dubbo", "Ignore Dubbo message. Drop tcp stream. Try parsing with the next segment")
		return priv
	}

	if complete {
		dubbo.messageComplete(tcptuple, dir, stream)
	}
	return private
}

func (dubbo *dubboPlugin) messageParser(s *dubboStream) (bool, bool) {
	data := s.data
	size := len(data)
	s.message.size = size

	// 打印字节切片中的所有字节
	fmt.Printf("Dubbo Header Bytes: %v\n", data)

	if size > 0 {
		//获取header。16个字节长度
		dubboHeader := data[:16]
		//判断是否为dubbo协议
		if isDubbo(dubboHeader) {

			ok, reqId := requestId(dubboHeader) //请求ID（作为关联请求响应）
			fmt.Printf("Dubbo Header reqId: %v\n", reqId)
			if ok {
				s.message.reqId = reqId
			}

			ok, length := bodyLength(dubboHeader) //获取body的长度
			if ok {
				ok, body := bodyByte(data, length)
				s.message.data = body
				if ok {
					if isRequest(dubboHeader) {
						s.message.isRequest = true
					} else {
						s.message.isRequest = false
					}
					return true, true
				}
			}
		}
	}
	return false, false
}

func convertToObj(data interface{}) (bool, interface{}) {
	if reflect.ValueOf(data).IsValid() {
		str := fmt.Sprintf("%v", data)
		return true, str
	} else {
		return false, ""
	}

	return true, fmt.Sprintf("%v", data)
	logp.Debug("dubbo", "convertToObj is err is")
	return false, nil
}

func doReq(body []byte, t *dubboTransaction) {
	for i := 0; i < 6; i++ {
		data, bodyUse := useByte(body)
		if i == 0 {
			if ok, m := convertToObj(data); ok {
				t.version = m.(string)
			}

		} else if i == 1 {
			if ok, m := convertToObj(data); ok {
				t.service = m.(string)
			}

		} else if i == 2 {
			if ok, m := convertToObj(data); ok {
				t.serviceVersion = m.(string)
			}

		} else if i == 3 {
			if ok, m := convertToObj(data); ok {
				t.method = m.(string)
			}

		} else if i == 4 {
			if ok, m := convertToObj(data); ok {
				t.paramType = m.(string)
			}

		} else if i == 5 {
			if ok, m := convertToObj(data); ok {
				logp.Debug("dubbo", "dubbo request is : %v", m)
				t.request = m
			}

		}
		//移除已经使用的字节
		if len(bodyUse) > 0 {
			body = body[len(bodyUse):]
		}
	}
}

func doRes(body []byte, t *dubboTransaction) {
	for i := 0; i < 2; i++ {
		data, bodyUse := useByte(body)
		if i == 1 {
			if ok, m := convertToObj(data); ok {
				t.response = m
			}
		}
		//移除已经使用的字节
		if len(bodyUse) > 0 {
			body = body[len(bodyUse):]
		}
	}
}

func useByte(body []byte) (interface{}, []byte) {
	if len(body) > 0 {
		//每次只读一个完整的数据字节，并不是读全部
		decodedObject, err := hessian.NewDecoder(body).Decode()
		if err == nil {
			encoder := hessian.NewEncoder()
			encoder.Encode(decodedObject)
			return decodedObject, encoder.Buffer()
		} else {
			logp.Err("can not hessian decoder err:", err)
		}
	}
	return nil, nil
}

// 判断是否为dubbo协议（以魔数判断）
func isDubbo(dubboHeader []byte) bool {
	if len(dubboHeader) < 2 {
		logp.Err("dubboHeader length is less than 2 bytes, unable to read Dubbo magic number")
		return false
	}
	// 读取前2个字节作为 Dubbo 魔数
	dubboMagic := dubboHeader[:2]
	// 判断 Dubbo 魔数是否匹配
	if !bytes.Equal(dubboMagic, []byte{0xda, 0xbb}) {
		logp.Err("Dubbo magic number not found. Got: %x\n", dubboMagic)
		return false
	}
	return true
}

// 判断是否为请求/响应
func isRequest(dubboHeader []byte) bool {
	if len(dubboHeader) < 2 {
		logp.Err("dubboHeader length is less than 3 bytes, unable to read Dubbo req/res flag")
		return false
	}
	// Extracting the 3 byte of Dubbo header
	flagByte := dubboHeader[2]
	reqResFlag := (flagByte & 0x80) >> 7
	//请求=1,响应=0
	return reqResFlag == 1
}

// 请求id，用此可以判断一次请求响应
func requestId(dubboHeader []byte) (bool, int64) {
	if len(dubboHeader) < 16 {
		logp.Err("dubboHeader length is less than 16 bytes, unable to read reqId length")
		return false, 0
	}
	requestId := int64(binary.BigEndian.Uint64(dubboHeader[4:12]))
	return true, requestId
}

// 获取body的长度
func bodyLength(dubboHeader []byte) (bool, int) {
	if len(dubboHeader) < 16 {
		logp.Err("dubboHeader length is less than 16 bytes, unable to read body length")
		return false, 0
	}
	messageLength := int(binary.BigEndian.Uint32(dubboHeader[12:16]))
	return true, messageLength
}

func bodyByte(payload []byte, length int) (bool, []byte) {
	if len(payload) < 16+length {
		logp.Err("unable to read body")
		return false, nil
	}
	data := payload[16 : 16+length]
	return true, data
}
func (dubbo *dubboPlugin) publishTransaction(t *dubboTransaction) {
	if dubbo.results == nil {
		return
	}

	logp.Debug("dubbo", "dubbo.results exists")

	evt, pbf := pb.NewBeatEvent(t.ts)
	pbf.SetSource(&t.src)
	pbf.AddIP(t.src.IP)
	pbf.SetDestination(&t.dst)
	pbf.AddIP(t.dst.IP)
	pbf.Source.Bytes = int64(t.bytesIn)
	pbf.Destination.Bytes = int64(t.bytesOut)
	pbf.Event.Dataset = "dubbo"
	pbf.Event.Start = t.ts
	pbf.Event.End = t.endTime
	pbf.Network.Transport = "tcp"
	pbf.Network.Protocol = "dubbo"
	pbf.Error.Message = t.notes

	fields := evt.Fields
	fields["type"] = pbf.Event.Dataset
	fields["serviceName"] = t.service
	fields["methodName"] = t.method
	fields["paramType"] = t.paramType
	if dubbo.sendRequest {
		fields["request"] = t.request
	}
	if dubbo.sendResponse {
		fields["response"] = t.response
	}

	dubbo.results(evt)
}
