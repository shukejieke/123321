package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"strconv"
	"stzbHelper/global"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var databaseSelected bool = false

func runNpcap() {
	// 获取所有网络接口
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal("无法获取网络接口列表:", err)
	}

	// 如果没有找到任何接口，退出
	if len(devices) == 0 {
		log.Fatal("未找到可用的网络接口")
	}

	if global.IsDebug == true {
		// 打印所有可用的网络接口
		fmt.Println("可用的网络接口:")
		for i, device := range devices {
			fmt.Printf("%d: %s (%s)\n", i+1, device.Name, device.Description)
		}
	}

	// 使用 WaitGroup 等待所有 Goroutine 完成
	var wg sync.WaitGroup

	for _, device := range devices {
		wg.Add(1)
		go captureTCPPackets(device.Name, &wg)
	}

	// 等待所有 Goroutine 完成
	wg.Wait()
}

// captureTCPPackets 监听指定接口的 TCP 数据包
func captureTCPPackets(deviceName string, wg *sync.WaitGroup) {
	defer wg.Done()

	// 打开网络接口
	handle, err := pcap.OpenLive(deviceName, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Printf("无法打开接口 %s: %v\n", deviceName, err)
		return
	}
	defer handle.Close()

	// 设置过滤器，只捕获端口为 8001 的 TCP 数据包
	filter := "tcp and port 8001"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Printf("无法在接口 %s 上设置过滤器: %v\n", deviceName, err)
		return
	}
	// 创建数据包源
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// 循环读取数据包
	if global.IsDebug == true {
		fmt.Printf("开始在接口 %s 上捕获 TCP 数据包（端口 8001）...\n", deviceName)
	}
	for packet := range packetSource.Packets() {
		handlePacket(packet)
	}
}

var fullbuf = []byte{}
var fullsize = 0
var waitbuf = false

type NetData struct {
	ID       int    `json:"id"`
	CmdId    int    `json:"cmd_id"`
	BufSize  int    `json:"bufsize"`
	Datatype int    `json:"datatype"`
	Data     string `json:"data"`
	Time     int64  `json:"time"`
	Dst      string `json:"dst"`
	Src      string `json:"src"`
	Type     int    `json:"type"`
}

func getTimestamp() int64 {
	now := time.Now()
	// 获取当前时间的时间戳（秒）
	//timestamp := now.Unix()
	millisecondsTimestamp := now.UnixNano() / int64(time.Millisecond)
	return millisecondsTimestamp
}

var Data []NetData

func handlePacket(packet gopacket.Packet) {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		if appLayer := packet.ApplicationLayer(); appLayer != nil {
			PSH := tcpLayer.(*layers.TCP).PSH
			payload := appLayer.Payload()
			if len(payload) < 8 {
				return
			}
			var srcIP string
			var dstIP string
			var srcProt int
			var dstProt int
			if ipLayer := packet.NetworkLayer(); ipLayer != nil {
				switch ip := ipLayer.(type) {
				case *layers.IPv4:
					srcProt = int(tcpLayer.(*layers.TCP).SrcPort)
					dstProt = int(tcpLayer.(*layers.TCP).DstPort)
					srcIP = ip.SrcIP.String() + ":" + strconv.Itoa(srcProt)
					dstIP = ip.DstIP.String() + ":" + strconv.Itoa(dstProt)
				case *layers.IPv6:
					srcProt = int(tcpLayer.(*layers.TCP).SrcPort)
					dstProt = int(tcpLayer.(*layers.TCP).DstPort)
					srcIP = ip.SrcIP.String() + ":" + strconv.Itoa(srcProt)
					dstIP = ip.DstIP.String() + ":" + strconv.Itoa(dstProt)
				}
			}

			if global.ExVar.BindIpInfo == true && global.OnlySrcIp != "" && global.OnlyDstIp != "" {
				if global.OnlySrcIp != srcIP || global.OnlyDstIp != dstIP {
					if global.IsDebug == true {
						fmt.Println("IP信息不符合跳过数据处理")
					}
					return
				}
			}

			var buf []byte
			if PSH != true {
				waitbuf = true
				fullbuf = append(fullbuf, payload...)
				return
			} else {
				if waitbuf == true {
					waitbuf = false
					buf = append(fullbuf, payload...)
					fullbuf = []byte{}
				} else {
					buf = payload
				}
			}

			if global.IsDebug == true {
				fmt.Println("")
				fmt.Println("====================================================")
				fmt.Println("")
			}
			bufread := NewBufferFrom(buf)
			bufsize := bufread.ReadInt()
			if global.IsDebug == true {
				fmt.Println("包大小", bufsize)
			}
			if dstProt == 8001 {
				bufread.ReadInt()
				bufread.ReadInt()
				bufread.ReadString(32)

			}
			cmdId := bufread.ReadInt()
			if global.IsDebug == true {
				fmt.Println("协议号", cmdId)
			}

			if dstProt == 8001 {
				bufread.ReadInt()
				bufread.ReadInt()
				bufread.ReadByte()
				for i, v := range bufread.Byte[bufread.offset:] {
					bufread.Byte[bufread.offset+i] = v ^ bufread.Byte[bufread.offset-2]
				}

				data := string(bufread.Byte[bufread.offset:])
				fmt.Println("发送内容", data)
				Data = append(Data, NetData{
					ID:       len(Data) + 1,
					CmdId:    cmdId,
					BufSize:  bufsize,
					Datatype: 5,
					Data:     data,
					Time:     getTimestamp(),
					Src:      srcIP,
					Dst:      dstIP,
					Type:     1,
				})
			} else if len(buf) > 14 {
				if global.IsDebug == true {
					fmt.Println("数据类型", buf[12])
					fmt.Println(srcIP, " -> ", dstIP)
				}

				if buf[12] == 3 {
					//fmt.Println(len(buf), bufsize, cmdId, "-----------")
					if len(buf)-bufsize != 4 {
						global.LossCmdId = cmdId
						global.LossBytes = buf
						global.PacketLoss = true
						global.NeedBufSize = bufsize
					} else {
						//go ParseData(cmdId, buf[17:])
						Data = append(Data, NetData{
							ID:       len(Data) + 1,
							CmdId:    cmdId,
							BufSize:  bufsize,
							Datatype: 3,
							Data:     string(parseZlibData(buf[17:])),
							Time:     getTimestamp(),
							Src:      srcIP,
							Dst:      dstIP,
						})
					}

				} else if buf[12] == 5 {
					//println(buf)
					//if global.IsDebug == true {
					//	data := DecodeType5(buf[12:])
					//	fmt.Println(data)
					//}
					Data = append(Data, NetData{
						ID:       len(Data) + 1,
						CmdId:    cmdId,
						BufSize:  bufsize,
						Datatype: 5,
						Data:     DecodeType5(buf[12:]),
						Time:     getTimestamp(),
						Src:      srcIP,
						Dst:      dstIP,
					})
				} else if buf[12] == 2 {
					Data = append(Data, NetData{
						ID:       len(Data) + 1,
						CmdId:    cmdId,
						BufSize:  bufsize,
						Datatype: 2,
						Data:     string(buf[13:]),
						Time:     getTimestamp(),
						Src:      srcIP,
						Dst:      dstIP,
					})
					//if cmdId == 5028 || cmdId == 5026 {
					//	fmt.Println(string(buf[12:]))
					//}
					//
					//if cmdId == 5028 {
					//	Parse5028(buf[13:])
					//}
				} else if cmdId > 99999 && global.PacketLoss == true {
					result := make([]byte, len(buf)+len(global.LossBytes))
					copy(result, global.LossBytes)
					copy(result[len(global.LossBytes):], buf)
					if len(buf)+len(global.LossBytes)-global.NeedBufSize != 4 {
						global.LossBytes = result
					} else {
						global.PacketLoss = false
						//go ParseData(global.LossCmdId, result[17:])
						Data = append(Data, NetData{
							ID:       len(Data) + 1,
							CmdId:    global.LossCmdId,
							BufSize:  bufsize,
							Datatype: 3,
							Data:     string(parseZlibData(result[17:])),
							Time:     getTimestamp(),
							Src:      srcIP,
							Dst:      dstIP,
						})
					}

				}

				//if cmdId == 3686 && databaseSelected == false {
				//	var data []byte
				//	if buf[12] == 5 {
				//		data = []byte(DecodeType5(buf[12:]))
				//	} else if buf[12] == 3 {
				//		data = parseZlibData(buf[17:])
				//	}
				//	var raw []interface{}
				//	err := json.Unmarshal([]byte(data), &raw)
				//	if err != nil {
				//		log.Fatal(err)
				//	} else {
				//		dataMap := raw[1].(map[string]interface{})
				//		server, ok := dataMap["server"].([]interface{})
				//		if ok {
				//			log.Printf("服务器信息: %v\n", server)
				//		}
				//
				//		var roleName string
				//		if logData, ok := dataMap["log"].(map[string]interface{}); ok {
				//			roleName = logData["role_name"].(string)
				//			log.Printf("角色名: %s\n", roleName)
				//		}
				//
				//		log.Println("本地IP：" + dstIP)
				//		log.Println("游戏服务器IP：" + srcIP)
				//		global.OnlySrcIp = srcIP
				//		global.OnlyDstIp = dstIP
				//		dabesename := roleName + "_" + server[0].(string)
				//		log.Println("收到主公簿数据，将打开数据库文件" + dabesename + ".db")
				//		model.InitDB(dabesename)
				//		databaseSelected = true
				//	}
				//}
			}

			if global.IsDebug == true {
				fmt.Print("[]byte{")
				for i, b := range buf {
					if i > 0 {
						fmt.Print(", ")
					}
					fmt.Print(b)
				}
				fmt.Println("}")
				fmt.Println("")
				fmt.Println("====================================================")
				fmt.Println("")
			}
		}
	}
}

type Buffer struct {
	Byte   []byte
	pos    int
	offset int
}

func (bb *Buffer) ResetOffset() {
	bb.offset = 0
}

func NewBufferFrom(b []byte) *Buffer {
	return &Buffer{Byte: b}
}

func (bb *Buffer) ReadInt() int {
	if bb.offset+4 > len(bb.Byte) {
		return 0
	}
	value := binary.BigEndian.Uint32(bb.Byte[bb.offset : bb.offset+4])
	bb.offset += 4
	return int(value)
}

func (bb *Buffer) ReadByte() byte {
	if bb.offset+1 > len(bb.Byte) {
		return 0
	}
	value := bb.Byte[bb.offset : bb.offset+1]
	bb.offset += 1
	return value[0]
}

func (bb *Buffer) ReadString(length int) string {
	if bb.offset+length > len(bb.Byte) {
		return ""
	}
	value := string(bb.Byte[bb.offset : bb.offset+length])
	bb.offset += length
	return value
}
