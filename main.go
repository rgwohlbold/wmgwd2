package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/pkg/errors"
	"github.com/rgwohlbold/arp"
	"github.com/rgwohlbold/rtnetlink"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

type Node struct {
	Uid      uint64
	LastSeen time.Time
}

type Assigner struct {
	PrevVnis map[uint64]struct{}
	Lock     sync.Mutex
}

const Port = 3000
const AdvertisementInterval = 1 * time.Second

const ArpInterval = 60 * time.Second

const BroadcastAddr = "10.0.1.255"

const MinVni = uint64(1)

const MaxVni = uint64(100)

const InterfacePattern = "vrrp4-%d"

var state map[uint64]Node
var stateLock = sync.Mutex{}
var nlConn *rtnetlink.Conn
var programStart time.Time

func murmur64(key uint64) uint64 {
	key ^= key >> 33
	key *= 0xff51afd7ed558ccd
	key ^= key >> 33
	key *= 0xc4ceb9fe1a85ec53
	key ^= key >> 33
	return key
}

func ToggleProtodown(interfaceName string, protodown bool) error {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to get interface %s", interfaceName))
	}
	if nlConn == nil {
		nlConn, err = rtnetlink.Dial(nil)
		if err != nil {
			return errors.Wrap(err, "failed to dial rtnetlink")
		}
	}

	msg, err := nlConn.Link.Get(uint32(iface.Index))
	if err != nil {
		nlConn.Close()
		nlConn = nil
		return errors.Wrap(err, fmt.Sprintf("failed to get link %s with index %d", interfaceName, iface.Index))
	}

	if protodown && msg.Attributes.OperationalState == rtnetlink.OperStateDown || !protodown && msg.Attributes.OperationalState == rtnetlink.OperStateUp {
		return nil
	}
	flags := uint32(0)
	if !protodown {
		flags = 1
	}

	err = nlConn.Link.Set(&rtnetlink.LinkMessage{
		Family: 0,
		Type:   msg.Type,
		Index:  uint32(iface.Index),
		Flags:  flags,
		Change: 1,
	})
	if err != nil {
		nlConn.Close()
		nlConn = nil
		return errors.Wrap(err, "failed to set link")
	}
	return nil

	//res := uint8(0)
	//if protodown {
	//	res = uint8(1)
	//}

	//err = nlConn.Link.Set(&rtnetlink.LinkMessage{
	//	Index: msg.Index,
	//	Attributes: &rtnetlink.LinkAttributes{
	//		ProtoDown: &res,
	//	}})
	//if err != nil {
	//	nlConn.Close()
	//	nlConn = nil
	//	return errors.Wrap(err, "failed to set link")
	//}
	//return nil
}

func Listen(ctx context.Context, ownUid uint64, assigner *Assigner) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		Port: Port,
		IP:   net.ParseIP(BroadcastAddr),
	})
	if err != nil {
		log.Fatal().Err(err).Msg("failed to listen")
	}
	defer conn.Close()
	log.Info().Str("addr", conn.LocalAddr().String()).Msg("server listening")

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		message := make([]byte, 9)
		err = conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
		if err != nil {
			log.Fatal().Err(err).Msg("could not set deadline")
		}
		rlen, _, err := conn.ReadFromUDP(message)
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Timeout() {
			} else {
				log.Error().Err(err).Msg("failed to read from udp")
			}
			continue
		}
		if rlen != 8 {
			log.Error().Msg("invalid message length")
			continue
		}
		uid := binary.BigEndian.Uint64(message[:8])
		stateLock.Lock()
		state[uid] = Node{
			Uid:      uid,
			LastSeen: time.Now(),
		}
		stateLock.Unlock()
		assigner.Assign(ownUid)
	}
}

func Advertise(ctx context.Context, Uid uint64) {
	raddr := &net.UDPAddr{
		IP:   net.ParseIP(BroadcastAddr),
		Port: Port,
	}

	bytes := make([]byte, 8)
	binary.BigEndian.PutUint64(bytes, Uid)

	ticker := time.NewTicker(AdvertisementInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			conn, err := net.DialUDP("udp", nil, raddr)
			if err != nil {
				log.Error().Err(err).Msg("could not dial udp")
				continue
			}
			_, err = conn.Write(bytes)
			if err != nil {
				log.Error().Err(err).Msg("could not write uid")
				err = conn.Close()
				if err != nil {
					log.Error().Err(err).Msg("could not close connection")
				}
				continue
			}
			err = conn.Close()
			if err != nil {
				log.Error().Err(err).Msg("could not close connection")
			}
		}
	}
}

func PutSelf(ctx context.Context, uid uint64) {
	ticker := time.NewTicker(AdvertisementInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stateLock.Lock()
			state[uid] = Node{Uid: uid, LastSeen: time.Now()}
			stateLock.Unlock()
		}
	}
}

func Assignee(nodes []uint64, vni uint64) uint64 {
	maxNode := nodes[0]
	maxHash := uint64(0)
	for _, node := range nodes {
		hash := murmur64(vni * node)
		if hash > maxHash {
			maxHash = hash
			maxNode = node
		}
	}
	return maxNode
}

func (a *Assigner) Assign(uid uint64) {
	// listen first, then start assigning
	if time.Now().Sub(programStart) < 3*AdvertisementInterval {
		return
	}
	a.Lock.Lock()
	defer a.Lock.Unlock()

	nodes := Nodes()
	if len(nodes) == 0 {
		return
	}
	vnis := make(map[uint64]struct{})
	for i := MinVni; i <= MaxVni; i++ {
		if Assignee(nodes, i) == uid {
			if _, ok := a.PrevVnis[i]; !ok {
				log.Info().Uint64("vni", i).Msg("assigning")
				err := ToggleProtodown(fmt.Sprintf(InterfacePattern, i), false)
				if err != nil {
					log.Error().Err(err).Msg("failed to toggle protodown")
				} else {
					vnis[i] = struct{}{}
				}
				err = SendGratuitousArp(i)
				if err != nil {
					log.Error().Err(err).Msg("failed to send gratuitous arp")
				}
			} else {
				vnis[i] = struct{}{}
			}
		} else {
			if _, ok := a.PrevVnis[i]; ok {
				log.Info().Uint64("vni", i).Msg("unassigning")
				err := ToggleProtodown(fmt.Sprintf(InterfacePattern, i), true)
				if err != nil {
					log.Error().Err(err).Msg("failed to toggle protodown")
					vnis[i] = struct{}{}
				}
			}
		}
	}
	a.PrevVnis = vnis
}

func Nodes() []uint64 {
	stateLock.Lock()
	defer stateLock.Unlock()
	nodes := make([]uint64, 0)
	for _, v := range state {
		if time.Now().Sub(v.LastSeen) < AdvertisementInterval*3 {
			nodes = append(nodes, v.Uid)
		}
	}
	return nodes
}

func ReassignOnExpiry(ctx context.Context, uid uint64, assigner *Assigner) {
	for {
		nextWakeup := AdvertisementInterval
		stateLock.Lock()
		for _, v := range state {
			expiry := AdvertisementInterval*3 - time.Now().Sub(v.LastSeen)
			if expiry > 0 && expiry < nextWakeup {
				nextWakeup = expiry
			}
		}
		stateLock.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(nextWakeup):
			assigner.Assign(uid)
		}
	}
}

func SendGratuitousArp(vni uint64) error {
	interfaceName := fmt.Sprintf(InterfacePattern, vni)
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return errors.Wrap(err, "could not get interface "+interfaceName)
	}
	client, err := arp.Dial(iface)
	if err != nil {
		return errors.Wrap(err, "could not dial arp")
	}
	defer client.Close()

	addrs, err := iface.Addrs()
	if err != nil {
		return errors.Wrap(err, "could not get interface addresses")
	}
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			return errors.Wrap(err, "could not parse cidr")
		}
		if ip.To4() != nil {
			nip, ok := netip.AddrFromSlice(ip.To4())
			if !ok {
				return errors.New("failed to convert ip to netip")
			}
			packet, err := arp.NewPacket(arp.OperationReply, iface.HardwareAddr, nip, net.HardwareAddr{0, 0, 0, 0, 0, 0}, nip)
			if err != nil {
				return errors.Wrap(err, "could not create arp packet")
			}
			err = client.WriteTo(packet, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
			if err != nil {
				return errors.Wrap(err, "could not write arp packet")
			}
		}
	}
	return nil
}

func PeriodicArp(ctx context.Context, uid uint64) {
	ticker := time.NewTicker(ArpInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			nodes := Nodes()
			for i := MinVni; i <= MaxVni; i++ {
				if Assignee(nodes, i) == uid {
					err := SendGratuitousArp(i)
					if err != nil {
						log.Error().Err(err).Msg("failed to send gratuitous arp")
					}
				}
			}
		}
	}
}

func main() {
	fileInfo, err := os.Stderr.Stat()
	if err != nil {
		log.Error().Err(err).Msg("failed to stat stderr")
	}
	if fileInfo.Mode()&os.ModeCharDevice != 0 {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	uidArg := flag.Uint64("uid", 0, "unique identifier for this node")
	flag.Parse()

	uid := rand.Uint64()
	if *uidArg != 0 {
		uid = *uidArg
	}

	state = make(map[uint64]Node)

	assigner := &Assigner{
		Lock:     sync.Mutex{},
		PrevVnis: make(map[uint64]struct{}),
	}

	for i := MinVni; i <= MaxVni; i++ {
		err = ToggleProtodown(fmt.Sprintf(InterfacePattern, i), true)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to toggle initial protodown")
		}
	}

	programStart = time.Now()

	go PutSelf(ctx, uid)
	go Advertise(ctx, uid)
	go Listen(ctx, uid, assigner)
	go ReassignOnExpiry(ctx, uid, assigner)
	go PeriodicArp(ctx, uid)

	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	<-c
	cancel()
	time.Sleep(3 * AdvertisementInterval)
	for i := MinVni; i <= MaxVni; i++ {
		err = ToggleProtodown(fmt.Sprintf(InterfacePattern, i), false)
		if err != nil {
			log.Error().Err(err).Msg("failed to toggle protodown")
		}
	}
}
