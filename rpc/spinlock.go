// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"runtime"
	"sync/atomic"
)

const (
	freed  int32 = 0
	locked int32 = 1
)

// SpinLock is an atomic lock to not keep CPU busy waiting
type SpinLock struct {
	state int32
}

// Lock
func (l *SpinLock) Lock() {
	for !atomic.CompareAndSwapInt32(&l.state, freed, locked) {
		runtime.Gosched()
	}
}

// Unlock
func (l *SpinLock) Unlock() {
	atomic.StoreInt32(&l.state, freed)
}
