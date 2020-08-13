// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package cmd

import (
	"encoding/pem"
	"fmt"
	"github.com/diodechain/diode_go_client/pkg/diode/crypto"
	"github.com/diodechain/diode_go_client/pkg/diode/db"
	"github.com/diodechain/diode_go_client/pkg/diode/util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"sort"
	"strings"
)

var (
	configCmd = &cobra.Command{
		Use:   "config",
		Short: "Manage variables in the local config store.",
		Long:  "Manage variables in the local config store.",
	}
)

func init() {
	listConfigCmd := &cobra.Command{
		Use:   "list",
		Short: "List all stored config keys.",
		Long:  "List all stored config keys.",
		RunE:  listConfigHandler,
	}
	listConfigCmd.Flags().Bool("unsafe", false, "display private keys (disabled by default)")
	viper.BindPFlag("unsafe", listConfigCmd.Flags().Lookup("unsafe"))
	deleteConfigCmd := &cobra.Command{
		Use:   "delete [key1] [key2]",
		Short: "Deletes the given variable from the config.",
		Long:  "Deletes the given variable from the config.",
		Args:  cobra.MinimumNArgs(1),
		RunE:  deleteConfigHandler,
	}
	setConfigCmd := &cobra.Command{
		Use:   "set [key1]=[0xvalue1] [key2]=[0xvalue2]",
		Short: "Sets the given variable in the config.",
		Long:  "Sets the given variable in the config.",
		Args:  cobra.MinimumNArgs(1),
		RunE:  setConfigHandler,
	}
	configCmd.AddCommand(listConfigCmd)
	configCmd.AddCommand(deleteConfigCmd)
	configCmd.AddCommand(setConfigCmd)
}

func listConfigHandler(cmd *cobra.Command, args []string) error {
	printLabel("<KEY>", "<VALUE>")
	list := db.DB.List()
	unsafe := viper.GetBool("unsafe")
	cfg := AppConfig
	sort.Strings(list)
	for _, name := range list {
		label := "<********************************>"
		value, err := db.DB.Get(name)
		if err == nil {
			if name == "private" {
				printLabel("<address>", cfg.ClientAddr.HexString())

				if unsafe {
					block, _ := pem.Decode(value)
					if block == nil {
						printError("Invalid pem private key format ", err)
						return err
					}
					privKey, err := crypto.DerToECDSA(block.Bytes)
					if err != nil {
						printError("Invalid der private key format ", err)
						return err
					}
					label = util.EncodeToString(privKey.D.Bytes())
				}
			} else {
				label = util.EncodeToString(value)
			}
		}
		printLabel(name, label)
	}
	fmt.Println(AppConfig.DBPath, AppConfig.Debug, AppConfig.RemoteRPCAddrs)
	return nil
}

func deleteConfigHandler(cmd *cobra.Command, args []string) (err error) {
	if len(args) > 0 {
		for _, deleteKey := range args {
			db.DB.Del(deleteKey)
			printLabel("Deleted:", deleteKey)
		}
	}
	return err
}

// TODO: set non hex value, maybe utf8 string or number
func setConfigHandler(cmd *cobra.Command, args []string) (err error) {
	if len(args) > 0 {
		for _, configSet := range args {
			list := strings.Split(configSet, "=")
			if len(list) == 2 {
				value := []byte(list[1])
				if util.IsHex(value) {
					value, err = util.DecodeString(list[1])
					if err != nil {
						printError("Couldn't decode hex string", err)
						return
					}
				}
				db.DB.Put(list[0], value)
				printLabel("Set:", list[0])
			} else {
				printError("Couldn't set value", fmt.Errorf("expected -set name=value format"))
				return
			}
		}
	}
	return err
}
