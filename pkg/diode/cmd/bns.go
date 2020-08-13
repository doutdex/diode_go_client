// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/diodechain/diode_go_client/pkg/diode/contract"
	"github.com/diodechain/diode_go_client/pkg/diode/edge"
	"github.com/diodechain/diode_go_client/pkg/diode/util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	bnsCmd = &cobra.Command{
		Use:   "bns",
		Short: "Register/Update name service on diode blockchain.",
		Long:  "Register/Update name service on diode blockchain.",
		RunE:  bnsHandler,
	}
	// ErrFailedToResetClient = fmt.Errorf("failed to reset diode client")
)

func init() {
	bnsCmd.Flags().String("lookup", "", "Lookup a given BNS name.")
	viper.BindPFlag("lookup", bnsCmd.Flags().Lookup("lookup"))
	bnsCmd.Flags().String("register", "", "Register a new BNS name with <name>=<address>.")
	viper.BindPFlag("register", bnsCmd.Flags().Lookup("register"))
}

func isValidBNS(name string) (isValid bool) {
	fmt.Println(name)
	if len(name) < 7 || len(name) > 32 {
		isValid = false
		return
	}
	isValid = bnsPattern.Match([]byte(name))
	return
}

func bnsHandler(cmd *cobra.Command, args []string) (err error) {
	err = app.Start()
	if err != nil {
		return
	}
	// register bns record
	bn, _ := client.GetBlockPeak()
	if bn == 0 {
		printError("Cannot find block peak: ", fmt.Errorf("not found"))
		return
	}
	cfg := AppConfig

	var nonce uint64
	var dnsContract contract.DNSContract
	dnsContract, err = contract.NewDNSContract()
	if err != nil {
		printError("Cannot create dns contract instance: ", err)
		return
	}
	registerFlag := viper.GetString("register")
	registerPair := strings.Split(registerFlag, "=")
	lookupName := viper.GetString("lookup")

	var obnsAddr util.Address
	if len(lookupName) > 0 {
		obnsAddr, err = client.ResolveBNS(lookupName)
		if err != nil {
			printError("Lookup error: ", err)
			return

		}
		printLabel("Lookup result: ", fmt.Sprintf("%s=0x%s", lookupName, obnsAddr.Hex()))
		return
	}

	if (len(registerPair) == 0 || len(registerPair) > 2) && len(lookupName) == 0 {
		printError("Argument Error: ", fmt.Errorf("provide -register <name>=<address> or -lookup <name> argument"))
		return
	}
	bnsName := registerPair[0]
	if !isValidBNS(bnsName) {
		printError("Argument Error: ", fmt.Errorf("BNS name should be more than 7 or less than 32 characters (0-9A-Za-z-)"))
		return
	}
	act, _ := client.GetValidAccount(uint64(bn), cfg.ClientAddr)
	if act == nil {
		nonce = 0
	} else {
		nonce = uint64(act.Nonce)
	}
	var bnsAddr util.Address
	if len(registerPair) > 1 {
		bnsAddr, err = util.DecodeAddress(registerPair[1])
		if err != nil {
			printError("Invalid diode address", err)
			return
		}
	} else {
		bnsAddr = cfg.ClientAddr
	}
	// check bns
	obnsAddr, err = client.ResolveBNS(bnsName)
	if err == nil {
		if obnsAddr == bnsAddr {
			printError("BNS name is already mapped to this address", err)
			return
		}
	}
	// send register transaction
	registerData, _ := dnsContract.Register(bnsName, bnsAddr)
	ntx := edge.NewTransaction(nonce, 0, 10000000, contract.DNSAddr, 0, registerData, 0)
	res, err := client.SendTransaction(ntx)
	if err != nil {
		printError("Cannot register blockchain name service: ", err)
		return
	}
	if !res {
		printError("Cannot register blockchain name service: ", fmt.Errorf("server return false"))
		return
	}
	printLabel("Register bns: ", fmt.Sprintf("%s=%s", bnsName, bnsAddr.HexString()))
	printInfo("Waiting for block to be confirmed - expect to wait 5 minutes")
	var current util.Address
	for i := 0; i < 6000; i++ {
		bn, _ = client.LastValid()
		current, err = client.ResolveBNS(bnsName)
		if err == nil && current == bnsAddr {
			printInfo("Registered bns successfully")
			return
		}
		for {
			bn2, _ := client.LastValid()
			if bn != bn2 {
				break
			}
			time.Sleep(time.Millisecond * 100)
		}
	}
	printError("Giving up to wait for transaction", fmt.Errorf("timeout after 10 minutes"))
	return
}
