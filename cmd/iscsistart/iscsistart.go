package main

import (
	"flag"
	"log"

	"github.com/u-root/iscsinl"
)

var (
	targetAddr      = flag.String("addr", "instance-1:3260", "target addr")
	volumeName      = flag.String("volume", "FOO", "volume name")
	monitorNetlink  = flag.Bool("monitorNetlink", false, "Set to true to monitor netlink socket until killed")
	teardownSession = flag.Int("teardownSid", -1, "Set to teardown a session")
	cmdsMax         = flag.Int("cmdsMax", 128, "Max outstanding iSCSI commands")
	queueDepth      = flag.Int("queueDepth", 16, "Max outstanding IOs")
	scheduler       = flag.String("scheduler", "noop", "block scheduler for session")
)

func main() {
	flag.Parse()

	if *teardownSession != -1 {
		if err := iscsinl.TearDownIscsi((uint32)(*teardownSession), 0); err != nil {
			log.Fatal(err)
		}
		return
	}

	device, err := iscsinl.MountIscsi(
		iscsinl.WithTarget(*targetAddr, *volumeName),
		iscsinl.WithCmdsMax(uint16(*cmdsMax)),
		iscsinl.WithQueueDepth(uint16(*queueDepth)),
		iscsinl.WithScheduler(*scheduler),
	)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Mounted at dev %v", device)
}
