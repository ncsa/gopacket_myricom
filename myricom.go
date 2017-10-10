// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package myricom

/*
#cgo linux LDFLAGS: -lsnf
#cgo freebsd LDFLAGS: -lsnf
#include <stdlib.h>
#include <snf.h>

// The things we do to avoid pointers escaping to the heap...
int pcap_next_ex_escaping(pcap_t *p, uintptr_t pkt_hdr, uintptr_t pkt_data) {
  return pcap_next_ex(p, (struct pcap_pkthdr**)(pkt_hdr), (const u_char**)(pkt_data));
}
*/
import "C"

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/google/gopacket"
)

func mustAtoiWithDefault(s string, defaultValue int) int {
	if s == "" {
		return defaultValue
	}
	i, err := strconv.Atoi(s)
	if err != nil {
		log.Fatal(err)
	}
	return i
}

const errorBufferSize = 256

// Handle provides a connection to a snf ring handle, allowing users to read packets
// off the wire (Next), inject packets onto the wire (Inject), and
// perform a number of other functions to affect and understand packet output.
//
type Handle struct {
	// cptr is the handle for the actual pcap C object.
	snf_handle  *C.snf_handle_t
	snf_ring    *C.snf_ring_t
	timeout     time.Duration
	timeoutms   int
	device      string
	deviceIndex int
	mu          sync.Mutex
	closeMu     sync.Mutex
	// stop is set to a non-zero value by Handle.Close to signal to
	// getNextBufPtrLocked to stop trying to read packets
	stop uint64

	// Since pointers to these objects are passed into a C function, if
	// they're declared locally then the Go compiler thinks they may have
	// escaped into C-land, so it allocates them on the heap.  This causes a
	// huge memory hit, so to handle that we store them here instead.
	recv_req C.struct_snf_rect_req
}

// Stats contains statistics on how many packets were handled by a pcap handle,
// and what was done with those packets.
type Stats struct {
	Nic_pkt_recv      int
	Nic_pkt_overflow  int
	Nic_pkt_bad       int
	Ring_pkt_recv     int
	Ring_pkt_overflow int
	Nic_bytes_recv    int
	Snf_pkt_overflow  int
	Nic_pkt_dropped   int
}

// BlockForever causes it to block forever waiting for packets, when passed
// into SetTimeout or OpenLive, while still returning incoming packets to userland relatively
// quickly.
const BlockForever = -time.Millisecond * 10

func timeoutMillis(timeout time.Duration) C.int {
	// Flip sign if necessary.  See package docs on timeout for reasoning behind this.
	if timeout < 0 {
		timeout *= -1
	}
	// Round up
	if timeout != 0 && timeout < time.Millisecond {
		timeout = time.Millisecond
	}
	return C.int(timeout / time.Millisecond)
}

// OpenLive opens a device and returns a *Handle.
// It takes as arguments the name of the device ("eth0"), the maximum size to
// read for each packet (snaplen), whether to put the interface in promiscuous
// mode, and a timeout.
//
// See the package documentation for important details regarding 'timeout'.
func OpenLive(device string, snaplen int32, promisc bool, timeout time.Duration) (handle *Handle, _ error) {

	if C.snf_init(C.SNF_VERSION_API) != 0 {
		return nil, fmt.Errorf("Myricom: failed in snf_init")
	}

	var ringnum int
	device_parts := strings.Split(device, ":")
	device = device_parts[0]
	if len(device_parts) > 1 {
		ringnum = mustAtoiWithDefault(device_parts[1], 0)
	}

	buf := (*C.char)(C.calloc(errorBufferSize, 1))
	defer C.free(unsafe.Pointer(buf))

	var pro C.int
	if promisc {
		pro = 1
	}
	p := &Handle{timeout: timeout, device: device}

	ifc, err := net.InterfaceByName(device)
	if err != nil {
		// The device wasn't found in the OS, but could be "any"
		// Set index to 0
		p.deviceIndex = 0
	} else {
		p.deviceIndex = ifc.Index
	}

	dev := C.CString(device)
	defer C.free(unsafe.Pointer(dev))

	snf_num_rings := mustAtoiWithDefault(os.Getenv("SNF_NUM_RINGS"), 1)

	//var rssp C.struct_snf_rss_params
	//rssp.mode = SNF_RSS_FLAGS

	snf_ring_size := 1024 // MB
	if C.snf_open(p.deviceIndex, snf_num_rings, nil, snf_ring_size, -1, &p.snf_handle) != 0 {
		return nil, fmt.Errorf("Myricom: failed in snf_open")
	}
	if C.snf_ring_open_id(p.snf_handle, ring_num, &p.snf_ring) {
		return nil, fmt.Errorf("Myricom: failed in snf_ring_open_id")
	}

	if C.snf_start(p.snf_handle) {
		return nil, fmt.Errorf("Myricom: failed in snf_start")
	}

	p.timeoutms = timeoutMillis(p.timeout)

	return p, nil
}

// NextError is the return code from a call to Next.
type NextError int32

// NextError implements the error interface.
func (n NextError) Error() string {
	switch n {
	case NextErrorOk:
		return "OK"
	case NextErrorTimeoutExpired:
		return "Timeout Expired"
	case NextErrorReadError:
		return "Read Error"
	case NextErrorNoMorePackets:
		return "No More Packets In File"
	case NextErrorNotActivated:
		return "Not Activated"
	}
	return strconv.Itoa(int(n))
}

// NextError values.
const (
	NextErrorOk             NextError = 1
	NextErrorTimeoutExpired NextError = 0
	NextErrorReadError      NextError = -1
	// NextErrorNoMorePackets is returned when reading from a file (OpenOffline) and
	// EOF is reached.  When this happens, Next() returns io.EOF instead of this.
	NextErrorNoMorePackets NextError = -2
	NextErrorNotActivated  NextError = -3
)

// ReadPacketData returns the next packet read from the pcap handle, along with an error
// code associated with that packet.  If the packet is read successfully, the
// returned error is nil.
func (p *Handle) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	p.mu.Lock()
	err = p.getNextBufPtrLocked(&ci)
	if err == nil {
		data = C.GoBytes(unsafe.Pointer(p.bufptr), C.int(ci.CaptureLength))
	}
	p.mu.Unlock()
	if err == NextErrorTimeoutExpired {
		runtime.Gosched()
	}
	return
}

type activateError C.int

const (
	aeNoError      = 0
	aeActivated    = C.PCAP_ERROR_ACTIVATED
	aePromisc      = C.PCAP_WARNING_PROMISC_NOTSUP
	aeNoSuchDevice = C.PCAP_ERROR_NO_SUCH_DEVICE
	aeDenied       = C.PCAP_ERROR_PERM_DENIED
	aeNotUp        = C.PCAP_ERROR_IFACE_NOT_UP
)

func (a activateError) Error() string {
	switch a {
	case aeNoError:
		return "No Error"
	case aeActivated:
		return "Already Activated"
	case aePromisc:
		return "Cannot set as promisc"
	case aeNoSuchDevice:
		return "No Such Device"
	case aeDenied:
		return "Permission Denied"
	case aeNotUp:
		return "Interface Not Up"
	default:
		return fmt.Sprintf("unknown activated error: %d", a)
	}
}

// getNextBufPtrLocked is shared code for ReadPacketData and
// ZeroCopyReadPacketData.
func (p *Handle) getNextBufPtrLocked(ci *gopacket.CaptureInfo) error {
	if p.cptr == nil {
		return io.EOF
	}

	for atomic.LoadUint64(&p.stop) == 0 {
		// try to read a packet if one is immediately available
		result := C.snf_ring_recv(p.snf_ring, p.timeoutms, &p.recv_req)
		switch result {
		case 0:
			if p.timeout >= 0 {
				return io.EOF
			}
		default:
			// got a packet, set capture info and return
			sec := int64(p.pkthdr.ts.tv_sec)
			// convert micros to nanos
			nanos := int64(p.pkthdr.ts.tv_usec) * 1000

			ci.Timestamp = time.Unix(sec, nanos)
			ci.CaptureLength = int(p.recv_req.length)
			ci.Length = int(p.recv_req.length)
			ci.InterfaceIndex = p.deviceIndex

			return nil
		}
	}

	// stop must be set
	return io.EOF
}

// ZeroCopyReadPacketData reads the next packet off the wire, and returns its data.
// The slice returned by ZeroCopyReadPacketData points to bytes owned by the
// the Handle.  Each call to ZeroCopyReadPacketData invalidates any data previously
// returned by ZeroCopyReadPacketData.  Care must be taken not to keep pointers
// to old bytes when using ZeroCopyReadPacketData... if you need to keep data past
// the next time you call ZeroCopyReadPacketData, use ReadPacketData, which copies
// the bytes into a new buffer for you.
//  data1, _, _ := handle.ZeroCopyReadPacketData()
//  // do everything you want with data1 here, copying bytes out of it if you'd like to keep them around.
//  data2, _, _ := handle.ZeroCopyReadPacketData()  // invalidates bytes in data1
func (p *Handle) ZeroCopyReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	p.mu.Lock()
	err = p.getNextBufPtrLocked(&ci)
	if err == nil {
		slice := (*reflect.SliceHeader)(unsafe.Pointer(&data))
		slice.Data = uintptr(unsafe.Pointer(p.recv_req.pkt_addr))
		slice.Len = ci.CaptureLength
		slice.Cap = ci.CaptureLength
	}
	p.mu.Unlock()
	if err == NextErrorTimeoutExpired {
		runtime.Gosched()
	}
	return
}

// Close closes the underlying snf handle.
func (p *Handle) Close() {
	p.closeMu.Lock()
	defer p.closeMu.Unlock()

	if p.snf_ring == nil {
		return
	}

	atomic.StoreUint64(&p.stop, 1)

	// wait for packet reader to stop
	p.mu.Lock()
	defer p.mu.Unlock()

	C.snf_ring_close(p.snf_ring)
	p.snf_ring = nil

	C.snf_close(p.snf_handle)
	p.snf_handle = nil
}

// Error returns the current error associated with a snf handle (pcap_geterr).
func (p *Handle) Error() error {
	return errors.New(C.GoString(strerror(errno)))
}

// Stats returns statistics on the underlying snf handle.
func (p *Handle) Stats() (stat *Stats, err error) {
	var cstats C.struct_snf_ring_stats
	if -1 == C.snf_ring_getstats(p.snf_ring, &cstats) {
		return nil, p.Error()
	}
	return &Stats{
		Nic_pkt_recv:      int(cstats.nic_pkt_recv),
		Nic_pkt_overflow:  int(cstats.nic_pkt_overflow),
		Nic_pkt_bad:       int(cstats.nic_pkt_bad),
		Ring_pkt_recv:     int(cstats.ring_pkt_recv),
		Ring_pkt_overflow: int(cstats.ring_pkt_overflow),
		Nic_bytes_recv:    int(cstats.nic_bytes_recv),
		Snf_pkt_overflow:  int(cstats.snf_pkt_overflow),
		Nic_pkt_dropped:   int(cstats.nic_pkt_dropped),
	}, nil
}

// SetBPFFilter compiles and sets a BPF filter for the pcap handle.
func (p *Handle) SetBPFFilter(expr string) (err error) {
	//TODO
	return nil
}

func statusError(status C.int) error {
	return errors.New(C.GoString(C.pcap_statustostr(status)))
}
