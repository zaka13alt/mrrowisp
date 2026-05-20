//go:build !linux

package wisp

import "net"

func setTCPLowLatency(_ net.Conn) {}

func rearmTCPQuickAck(_ net.Conn) {}
