package main

import (
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

type blockList struct {
	enabled  bool
	maxRetry int
	banTime  int
	findTime int
	ignoreIP string

	ignoreIPNet *net.IPNet
	events      []blockListEvent
	blocked     map[string]int64
}

type blockListEvent struct {
	host   string
	time   int64
	status bool
}

func newBlockList() (*blockList, error) {
	// defaults
	// TODO: ignoreIP multiple CIDRs
	b := blockList{
		enabled:  false,
		maxRetry: 3,
		banTime:  600,
		findTime: 600,
		ignoreIP: "127.0.0.1/8",

		events:  []blockListEvent{},
		blocked: map[string]int64{},
	}

	_, b.ignoreIPNet, _ = net.ParseCIDR(b.ignoreIP)

	return &b, nil
}

func (b *blockList) SetIgnoreIP(s string) {
	b.ignoreIP = s
	// TODO: error handling?
	_, b.ignoreIPNet, _ = net.ParseCIDR(b.ignoreIP)
}

func (b *blockList) addEvent(e blockListEvent) {
	if !b.enabled {
		return
	}

	// check if IP is not within ignored ranges
	ip := net.ParseIP(e.host)
	if b.ignoreIPNet.Contains(ip) {
		log.Debugf("remote IP within ignored ranges for automatic blocking: %s", e.host)
		return
	}

	if e.status {
		// drop host events history on successful login
		b.deleteHostEvents(e.host)
	} else {
		// cleanup historic data
		b.garbageCollect()

		// skip events if host already blocked
		_, ok := b.blocked[e.host]

		if !ok {
			// append new event
			b.events = append(b.events, e)

			// count host failures
			count := 0

			for _, event := range b.events {
				if event.host == e.host {
					count++

					// add host to blocklist and delete his events
					if count >= b.maxRetry {
						log.Infof("blocking remote host %s after %d failures", e.host, count)
						b.blockHost(e.host)
						break
					}
				}
			}
		}
	}
}

func (b blockList) isBlocked(host string) bool {
	b.garbageCollect()

	_, ok := b.blocked[host]
	log.Tracef("checking if remote IP %s is blocked: %t", host, ok)
	return ok
}

func (b blockList) isBlockedAddr(addr net.Addr) bool {
	s, _, _ := net.SplitHostPort(addr.String())
	return b.isBlocked(s)
}

func (b *blockList) deleteHostEvents(host string) {
	newEvents := []blockListEvent{}

	for _, event := range b.events {
		if event.host != host {
			newEvents = append(newEvents, event)
		}
	}

	b.events = newEvents
}

func (b *blockList) blockHost(host string) {
	// add host to blocklist and delete his events
	b.blocked[host] = time.Now().Unix() + int64(b.banTime)
	b.deleteHostEvents(host)
}

func (b *blockList) garbageCollect() {
	if !b.enabled {
		return
	}

	now := time.Now().Unix()

	// cleanup event list
	thresholdTime := now - int64(b.findTime)

	for index, event := range b.events {
		// find first event which fits into our window and remove
		// all previous events which are too old to consider
		if event.time >= thresholdTime {
			b.events = b.events[index:]
			break
		}

		// we have reached end of slice without encountering
		// event to preserve -> drop it all
		if index == len(b.events)-1 {
			b.events = []blockListEvent{}
		}
	}

	// cleanup block list
	for host, expire := range b.blocked {
		if expire < now {
			log.Infof("unblocking remote host %s", host)
			delete(b.blocked, host)
		}
	}
}

func (b *blockList) dumpEvents() {
	log.Debugf("---\nDump:\n")
	for index, event := range b.events {
		log.Debugf("%d: %s %d\n", index, event.host, event.time)
	}
	log.Debugf("---\n")
}
