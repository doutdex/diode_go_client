// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package cmd

import (
	"fmt"

	"github.com/diodechain/diode_go_client/pkg/diode/config"
	"github.com/diodechain/diode_go_client/pkg/diode/rpc"
	"github.com/spf13/cobra"
)

var (
	socksdCmd = &cobra.Command{
		Use:   "socksd",
		Short: "Enable a socks proxy for use with browsers and other apps.",
		Long:  "Enable a socks proxy for use with browsers and other apps.",
		RunE:  socksdHandler,
	}
)

func init() {
	socksdCmd.Flags().StringVar(&AppConfig.SocksServerHost, "socksd_host", "127.0.0.1", "host of socks server listening to")
	socksdCmd.Flags().IntVar(&AppConfig.SocksServerPort, "socksd_port", 1080, "port of socks server listening to")
	socksdCmd.Flags().StringVar(&AppConfig.SocksFallback, "fallback", "localhost", "how to resolve web2 addresses")
}

func socksdHandler(cmd *cobra.Command, args []string) (err error) {
	err = app.Start()
	if err != nil {
		return
	}
	client := app.GetClientByOrder(1)
	if client == nil {
		err = ErrFailedToConnectServer
		return
	}
	socksServer := client.NewSocksServer(app.clientpool, app.datapool)
	socksServer.SetConfig(&rpc.Config{
		Addr:            AppConfig.SocksServerAddr(),
		FleetAddr:       AppConfig.FleetAddr,
		Blocklists:      AppConfig.Blocklists,
		Allowlists:      AppConfig.Allowlists,
		EnableProxy:     AppConfig.EnableProxyServer,
		ProxyServerAddr: AppConfig.ProxyServerAddr(),
		Fallback:        AppConfig.SocksFallback,
	})
	if len(AppConfig.Binds) > 0 {
		socksServer.SetBinds(AppConfig.Binds)
		printInfo("")
		printLabel("Bind      <name>", "<mode>     <remote>")
		for _, bind := range AppConfig.Binds {
			printLabel(fmt.Sprintf("Port      %5d", bind.LocalPort), fmt.Sprintf("%5s     %11s:%d", config.ProtocolName(bind.Protocol), bind.To, bind.ToPort))
		}
	}
	app.SetSocksServer(socksServer)
	if err = socksServer.Start(); err != nil {
		AppConfig.Logger.Error(err.Error())
		return
	}
	app.Wait()
	return
}
