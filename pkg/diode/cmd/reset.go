// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package cmd

import (
	"fmt"

	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/contract"
	"github.com/diodechain/diode_go_client/db"
	"github.com/diodechain/diode_go_client/edge"
	"github.com/diodechain/diode_go_client/rpc"
	"github.com/diodechain/diode_go_client/util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	resetCmd = &cobra.Command{
		Use:   "reset",
		Short: "Initialize a new account and a new fleet contract in the network. WARNING: this will delete current credentials!",
		Long:  "Initialize a new account and a new fleet contract in the network. WARNING: this will delete current credentials!",
		RunE:  resetHandler,
	}
	ErrFailedToResetClient = fmt.Errorf("failed to reset diode client")
)

func init() {
	resetCmd.Flags().Bool("experimental", false, "send transactions of fleet deployment and device allowlist at seme time")
	viper.BindPFlag("experimental", resetCmd.Flags().Lookup("experimental"))
}

func resetHandler(cmd *cobra.Command, args []string) (err error) {
	err = app.Start()
	if err != nil {
		return
	}
	var ret int
	experimental := viper.GetBool("experimental")
	if experimental {
		ret = doInit(AppConfig, client)
	} else {
		ret = doInitExp(AppConfig, client)
	}
	if ret != 0 {
		err = ErrFailedToResetClient
	}
	return
}

func doInit(cfg *config.Config, client *rpc.RPCClient) (status int) {
	if cfg.FleetAddr != config.DefaultFleetAddr {
		printInfo("Your client has been already initialized, try to publish or browse through Diode Network.")
		return
	}
	// deploy fleet
	bn, _ := client.GetBlockPeak()
	if bn == 0 {
		printError("Cannot find block peak: ", fmt.Errorf("not found"))
		status = 129
		return
	}

	var nonce uint64
	var fleetContract contract.FleetContract
	var err error
	fleetContract, err = contract.NewFleetContract()
	if err != nil {
		printError("Cannot create fleet contract instance: ", err)
		status = 129
		return
	}
	act, _ := client.GetValidAccount(uint64(bn), cfg.ClientAddr)
	if act == nil {
		nonce = 0
	} else {
		nonce = uint64(act.Nonce)
	}
	deployData, err := fleetContract.DeployFleetContract(cfg.RegistryAddr, cfg.ClientAddr, cfg.ClientAddr)
	if err != nil {
		printError("Cannot create deploy contract data: ", err)
		status = 129
		return
	}
	tx := edge.NewDeployTransaction(nonce, 0, 10000000, 0, deployData, 0)
	res, err := client.SendTransaction(tx)
	if err != nil {
		printError("Cannot deploy fleet contract: ", err)
		status = 129
		return
	}
	if !res {
		printError("Cannot deploy fleet contract: ", fmt.Errorf("server return false"))
		status = 129
		return
	}
	fleetAddr := util.CreateAddress(cfg.ClientAddr, nonce)
	printLabel("New fleet address", fleetAddr.HexString())
	printInfo("Waiting for block to be confirmed - this can take up to a minute")
	watchAccount(client, fleetAddr)
	printInfo("Created fleet contract successfully")
	// generate fleet address
	// send device allowlist transaction
	allowlistData, _ := fleetContract.SetDeviceAllowlist(cfg.ClientAddr, true)
	ntx := edge.NewTransaction(nonce+1, 0, 10000000, fleetAddr, 0, allowlistData, 0)
	res, err = client.SendTransaction(ntx)
	if err != nil {
		printError("Cannot allowlist device: ", err)
		status = 129
		return
	}
	if !res {
		printError("Cannot allowlist device: ", fmt.Errorf("server return false"))
		status = 129
		return
	}
	printLabel("Allowlisting device: ", cfg.ClientAddr.HexString())
	printInfo("Waiting for block to be confirmed - this can take up to a minute")
	watchAccount(client, fleetAddr)
	printInfo("Allowlisted device successfully")
	cfg.FleetAddr = fleetAddr
	if cfg.LoadFromFile {
		err = cfg.SaveToFile()
	} else {
		err = db.DB.Put("fleet", fleetAddr[:])
	}
	if err != nil {
		printError("Cannot save fleet address: ", err)
		status = 129
		return
	}
	printInfo("Client has been initialized, try to publish or browser through Diode Network.")
	return
}

func doInitExp(cfg *config.Config, client *rpc.RPCClient) (status int) {
	if cfg.FleetAddr != config.DefaultFleetAddr {
		printInfo("Your client has been already initialized, try to publish or browse through Diode Network.")
		return
	}
	// deploy fleet
	bn, _ := client.GetBlockPeak()
	if bn == 0 {
		printError("Cannot find block peak: ", fmt.Errorf("not found"))
		status = 129
		return
	}

	var nonce uint64
	var fleetContract contract.FleetContract
	var err error
	fleetContract, err = contract.NewFleetContract()
	if err != nil {
		printError("Cannot create fleet contract instance: ", err)
		status = 129
		return
	}
	act, _ := client.GetValidAccount(uint64(bn), cfg.ClientAddr)
	if act == nil {
		nonce = 0
	} else {
		nonce = uint64(act.Nonce)
	}
	deployData, err := fleetContract.DeployFleetContract(cfg.RegistryAddr, cfg.ClientAddr, cfg.ClientAddr)
	if err != nil {
		printError("Cannot create deploy contract data: ", err)
		status = 129
		return
	}
	tx := edge.NewDeployTransaction(nonce, 0, 10000000, 0, deployData, 0)
	res, err := client.SendTransaction(tx)
	if err != nil {
		printError("Cannot deploy fleet contract: ", err)
		status = 129
		return
	}
	if !res {
		printError("Cannot deploy fleet contract: ", fmt.Errorf("server return false"))
		status = 129
		return
	}
	fleetAddr := util.CreateAddress(cfg.ClientAddr, nonce)
	printLabel("New fleet address", fleetAddr.HexString())
	// generate fleet address
	// send device allowlist transaction
	allowlistData, _ := fleetContract.SetDeviceAllowlist(cfg.ClientAddr, true)
	ntx := edge.NewTransaction(nonce+1, 0, 10000000, fleetAddr, 0, allowlistData, 0)
	res, err = client.SendTransaction(ntx)
	if err != nil {
		printError("Cannot allowlist device: ", err)
		status = 129
		return
	}
	if !res {
		printError("Cannot allowlist device: ", fmt.Errorf("server return false"))
		status = 129
		return
	}
	printLabel("Allowlisting device: ", cfg.ClientAddr.HexString())
	printInfo("Waiting for block to be confirmed - this can take up to a minute")
	watchAccount(client, fleetAddr)
	printInfo("Created fleet contract and allowlisted device successfully")
	cfg.FleetAddr = fleetAddr
	if cfg.LoadFromFile {
		err = cfg.SaveToFile()
	} else {
		err = db.DB.Put("fleet", fleetAddr[:])
	}
	if err != nil {
		printError("Cannot save fleet address: ", err)
		status = 129
		return
	}
	printInfo("Client has been initialized, try to publish or browser through Diode Network.")
	return
}
