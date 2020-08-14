// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package cmd

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/diodechain/diode_go_client/pkg/diode/config"
	"github.com/diodechain/diode_go_client/pkg/diode/util"
	"github.com/spf13/cobra"
	// "github.com/spf13/viper"
)

var (
	portPattern   = regexp.MustCompile(`^(\d+)(:(\d*)(:(tcp|tls|udp))?)?$`)
	accessPattern = regexp.MustCompile(`^0x[a-fA-F0-9]{40}$`)
	publishCmd    = &cobra.Command{
		Use:   "publish",
		Short: "Publish ports of the local device to the Diode Network.",
		Long:  "Publish ports of the local device to the Diode Network.",
		RunE:  publishHandler,
	}
)

func init() {
	publishCmd.Flags().StringSliceVar(&AppConfig.PublicPublishedPorts, "public", emptyStringSlice, "expose ports to public users, so that user could connect to")
	publishCmd.Flags().StringSliceVar(&AppConfig.ProtectedPublishedPorts, "protected", emptyStringSlice, "expose ports to protected users (in fleet contract), so that user could connect to")
	publishCmd.Flags().StringSliceVar(&AppConfig.PrivatePublishedPorts, "private", emptyStringSlice, "expose ports to private users, so that user could connect to")
	publishCmd.Flags().StringVar(&AppConfig.SocksServerHost, "proxy_host", "127.0.0.1", "host of socksd proxy server")
	publishCmd.Flags().IntVar(&AppConfig.SocksServerPort, "proxy_port", 1080, "port of socksd proxy server")
	publishCmd.Flags().BoolVar(&AppConfig.EnableSocksServer, "socksd", false, "enable socksd proxy server")
}

func parsePorts(portStrings []string, mode int, enableEdgeE2E bool) ([]*config.Port, error) {
	ports := []*config.Port{}
	for _, portString := range portStrings {
		segments := strings.Split(portString, ",")
		allowlist := make(map[util.Address]bool)
		for _, segment := range segments {
			portDef := portPattern.FindStringSubmatch(segment)
			// fmt.Printf("%+v (%v)\n", portDef, len(portDef))

			if len(portDef) >= 2 {
				srcPort, err := strconv.Atoi(portDef[1])
				if err != nil {
					return nil, fmt.Errorf("src port number expected but got: %v in %v", portDef[1], segment)
				}
				if !util.IsPort(srcPort) {
					return nil, fmt.Errorf("src port number should be bigger than 1 and smaller than 65535")
				}
				var toPort int
				if len(portDef) < 4 || portDef[3] == "" {
					toPort = srcPort
				} else {
					toPort, err = strconv.Atoi(portDef[3])
					if err != nil {
						return nil, fmt.Errorf("to port number expected but got: %v in %v", portDef[3], segment)
					}
					if !util.IsPort(toPort) {
						return nil, fmt.Errorf("to port number should be bigger than 1 and smaller than 65535")
					}
				}

				port := &config.Port{
					Src:       srcPort,
					To:        toPort,
					Mode:      mode,
					Protocol:  AnyProtocol,
					Allowlist: allowlist,
				}

				if len(portDef) >= 6 {
					switch portDef[5] {
					case "tls":
						if !enableEdgeE2E {
							return nil, fmt.Errorf("should enable e2e to use tle protocol")
						}
						port.Protocol = TLSProtocol
					case "tcp":
						port.Protocol = TCPProtocol
					case "udp":
						port.Protocol = UDPProtocol
					case "any":
						port.Protocol = AnyProtocol
					case "":
						port.Protocol = AnyProtocol
					default:
						return nil, fmt.Errorf("port unknown protocol %v in: %v", portDef[4], segment)
					}
				}
				ports = append(ports, port)
			} else {
				access := accessPattern.FindString(segment)
				if access == "" {
					return nil, fmt.Errorf("port format expected <from>:<to>(:<protocol>) or <address> but got: %v", segment)
				}

				addr, err := util.DecodeAddress(access)
				if err != nil {
					return nil, fmt.Errorf("port format couldn't parse port address: %v", segment)
				}

				allowlist[addr] = true
			}
		}
	}

	for _, v := range ports {
		if mode == PublicPublishedMode && len(v.Allowlist) > 0 {
			return nil, fmt.Errorf("public port publishing does not support providing addresses")
		}
		if mode == PrivatePublishedMode && len(v.Allowlist) == 0 {
			return nil, fmt.Errorf("private port publishing reuquires providing at least one address")
		}
		// limit fleet address size when publish protected port
		if mode == ProtectedPublishedMode && len(v.Allowlist) > 5 {
			return nil, fmt.Errorf("fleet address size should not exceeds 5 when publish protected port")
		}
	}

	return ports, nil
}

// TODO: publish to another client if first client is closed
func publishHandler(cmd *cobra.Command, args []string) (err error) {
	// copy to config
	var ports []*config.Port
	cfg := AppConfig
	ports, err = parsePorts(cfg.PublicPublishedPorts, PublicPublishedMode, cfg.EnableEdgeE2E)
	if err != nil {
		return
	}
	portString := make(map[int]*config.Port)
	for _, port := range ports {
		if portString[port.To] != nil {
			return fmt.Errorf("public port specified twice: %v", port.To)
		}
		portString[port.To] = port
	}
	ports, err = parsePorts(cfg.ProtectedPublishedPorts, ProtectedPublishedMode, cfg.EnableEdgeE2E)
	if err != nil {
		return
	}
	for _, port := range ports {
		if portString[port.To] != nil {
			return fmt.Errorf("port conflict between public and protected port: %v", port.To)
		}
		portString[port.To] = port
	}
	ports, err = parsePorts(cfg.PrivatePublishedPorts, PrivatePublishedMode, cfg.EnableEdgeE2E)
	if err != nil {
		return
	}
	for _, port := range ports {
		if portString[port.To] != nil {
			return fmt.Errorf("port conflict with private port: %v", port.To)
		}
		portString[port.To] = port
	}
	cfg.PublishedPorts = portString
	err = app.Start()
	if err != nil {
		return
	}
	client := app.GetClientByOrder(1)
	if client == nil {
		err = ErrFailedToConnectServer
		return
	}
	app.PublishPorts()
	app.Wait()
	return
}
