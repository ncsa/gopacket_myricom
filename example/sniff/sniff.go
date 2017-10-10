package main

import (
	"log"
	"os"
	"runtime"
	"runtime/pprof"

	myricom "github.com/ncsa/gopacket_myricom"
)

func main() {

	var err error
	handle, err := myricom.OpenLive(os.Args[1], 9000, true, myricom.BlockForever)
	if err != nil {
		panic(err)
	}
	cf, err := os.Create("sniff.cpuprofile")
	if err != nil {
		log.Fatal(err)
	}
	pprof.StartCPUProfile(cf)
	defer pprof.StopCPUProfile()
	var m runtime.MemStats
	for i := 0; i < 1000000; i++ {
		_, _, err := handle.ZeroCopyReadPacketData()
		if err != nil {
			println(err)
		}
		if i%100000 == 0 {
			runtime.ReadMemStats(&m)
			log.Printf("Alloc = %v TotalAlloc = %v Sys = %v NumGC = %v\n", m.Alloc/1024, m.TotalAlloc/1024, m.Sys/1024, m.NumGC)
		}
	}

	f, err := os.Create("sniff.profile")
	if err != nil {
		log.Fatal(err)
	}
	pprof.WriteHeapProfile(f)
	f.Close()
}
