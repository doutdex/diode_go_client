// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	// "github.com/diodechain/diode_go_client/pkg/diode/config"
	// "io/ioutil"
	// "log"
	// "net"
	// "net/http"
	// "net/url"
	// "sync"
	"github.com/diodechain/diode_go_client/pkg/diode/rpc"
	"time"
)

var (
	timeCmd = &cobra.Command{
		Use:   "time",
		Short: "Lookup the current time from the blockchain consensus.",
		Long:  "Lookup the current time from the blockchain consensus.",
		RunE:  timeHandler,
	}
	ErrFailedToFetchHeader   = fmt.Errorf("can't load last valid block")
	ErrFailedToConnectServer = fmt.Errorf("can't connect to server")
)

func timeHandler(cmd *cobra.Command, args []string) (err error) {
	err = app.Start()
	if err != nil {
		return
	}
	client := app.GetClientByOrder(1)
	if client == nil {
		err = ErrFailedToConnectServer
		return
	}
	blocknr, _ := client.LastValid()
	header := client.GetBlockHeaderValid(blocknr)
	if header == nil {
		printError("Time retrieval error: ", fmt.Errorf("can't load last valid block %d", blocknr))
		return ErrFailedToFetchHeader
	}

	t0 := int(header.Timestamp())
	t1 := t0 + (rpc.WindowSize() * AverageBlockTime)

	tm0 := time.Unix(int64(t0), 0)
	tm1 := time.Unix(int64(t1), 0)
	printLabel("Minimum Time", fmt.Sprintf("%s (%d)", tm0.Format(time.UnixDate), t0))
	printLabel("Maximum Time", fmt.Sprintf("%s (%d)", tm1.Format(time.UnixDate), t1))
	return
}
