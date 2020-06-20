// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package contract

import (
	"strings"

	"github.com/diodechain/diode_go_client/accounts/abi"
	"github.com/diodechain/diode_go_client/crypto"
	"github.com/diodechain/diode_go_client/util"
)

/**
 * The storage position of registry contract
 */
const (
	DNSOperatorIndex = iota
	DNSNamesIndex
	DNSContractABI = `[{"constant":true,"inputs":[{"name":"","type":"bytes32"}],"name":"names","outputs":[{"name":"destination","type":"address"},{"name":"owner","type":"address"},{"name":"name","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"name","type":"string"}],"name":"Resolve","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"name","type":"string"},{"name":"destination","type":"address"}],"name":"Register","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"operator","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"inputs":[{"name":"_operator","type":"address"}],"payable":false,"stateMutability":"nonpayable","type":"constructor"}]`
	DNSContractBin = "0x608060405234801561001057600080fd5b506040516020806109ec833981016040525160008054600160a060020a03909216600160a060020a031990921691909117905561099a806100526000396000f3006080604052600436106100615763ffffffff7c010000000000000000000000000000000000000000000000000000000060003504166320c38e2b811461006657806333f0260a146101285780633e49fb7e1461019d578063570ca73514610203575b600080fd5b34801561007257600080fd5b5061007e600435610218565b6040518084600160a060020a0316600160a060020a0316815260200183600160a060020a0316600160a060020a0316815260200180602001828103825283818151815260200191508051906020019080838360005b838110156100eb5781810151838201526020016100d3565b50505050905090810190601f1680156101185780820380516001836020036101000a031916815260200191505b5094505050505060405180910390f35b34801561013457600080fd5b506040805160206004803580820135601f81018490048402850184019095528484526101819436949293602493928401919081908401838280828437509497506102d19650505050505050565b60408051600160a060020a039092168252519081900360200190f35b3480156101a957600080fd5b506040805160206004803580820135601f810184900484028501840190955284845261020194369492936024939284019190819084018382808284375094975050509235600160a060020a0316935061030092505050565b005b34801561020f57600080fd5b506101816104ff565b6001602081815260009283526040928390208054818401546002808401805488516101009882161598909802600019011691909104601f8101869004860287018601909752868652600160a060020a0392831696929091169492939091908301828280156102c75780601f1061029c576101008083540402835291602001916102c7565b820191906000526020600020905b8154815290600101906020018083116102aa57829003601f168201915b5050505050905083565b6000600160006102e08461050e565b8152602081019190915260400160002054600160a060020a031692915050565b600061030a6108b4565b61031384610572565b61031c8461050e565b60008181526001602081815260409283902083516060810185528154600160a060020a039081168252828501541681840152600280830180548751601f9782161561010002600019019091169290920495860185900485028201850187528582529698509095919486019390928301828280156103da5780601f106103af576101008083540402835291602001916103da565b820191906000526020600020905b8154815290600101906020018083116103bd57829003601f168201915b505050919092525050506020810151909150600160a060020a0316158061040d57506020810151600160a060020a031633145b1515610463576040805160e560020a62461bcd02815260206004820152601a60248201527f54686973206e616d6520697320616c72656164792074616b656e000000000000604482015290519081900360640190fd5b600160a060020a038084168252602082015116151561048a57336020820152604081018490525b60008281526001602081815260409283902084518154600160a060020a0391821673ffffffffffffffffffffffffffffffffffffffff199182161783558387015194830180549590921694169390931790925591830151805184936104f69260028501929101906108d3565b50505050505050565b600054600160a060020a031681565b6000816040518082805190602001908083835b602083106105405780518252601f199092019160209182019101610521565b5181516020939093036101000a6000190180199091169216919091179052604051920182900390912095945050505050565b8051819060009081906007106105f8576040805160e560020a62461bcd02815260206004820152602660248201527f4e616d6573206d757374206265206c6f6e676572207468616e2037206368617260448201527f6163746572730000000000000000000000000000000000000000000000000000606482015290519081900360840190fd5b825160201015610678576040805160e560020a62461bcd02815260206004820152602260248201527f4e616d6573206d7573742062652077697468696e20333220636861726163746560448201527f7273000000000000000000000000000000000000000000000000000000000000606482015290519081900360840190fd5b82518210156108ae57828281518110151561068f57fe5b01602001517f0100000000000000000000000000000000000000000000000000000000000000908190040290507f3000000000000000000000000000000000000000000000000000000000000000600160f860020a031982161080159061072057507f3900000000000000000000000000000000000000000000000000000000000000600160f860020a0319821611155b8061078a57507f4100000000000000000000000000000000000000000000000000000000000000600160f860020a031982161080159061078a57507f5a00000000000000000000000000000000000000000000000000000000000000600160f860020a0319821611155b806107f457507f6100000000000000000000000000000000000000000000000000000000000000600160f860020a03198216108015906107f457507f7a00000000000000000000000000000000000000000000000000000000000000600160f860020a0319821611155b8061082857507f2d00000000000000000000000000000000000000000000000000000000000000600160f860020a03198216145b15156108a3576040805160e560020a62461bcd028152602060048201526024808201527f4e616d65732063616e206f6e6c7920636f6e7461696e3a205b302d39412d5a6160448201527f2d7a2d5d00000000000000000000000000000000000000000000000000000000606482015290519081900360840190fd5b600190910190610678565b50505050565b6040805160608181018352600080835260208301529181019190915290565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f1061091457805160ff1916838001178555610941565b82800160010185558215610941579182015b82811115610941578251825591602001919060010190610926565b5061094d929150610951565b5090565b61096b91905b8082111561094d5760008155600101610957565b905600a165627a7a723058200f1e664c39039be0174c58df46775cfb29023b05c10e648101abf23aa0c9e3630029"
)

var DNSAddr = [20]byte{175, 96, 250, 165, 205, 132, 11, 114, 71, 66, 241, 175, 17, 97, 104, 39, 97, 18, 214, 166}

// DNSContract is fleet contract struct
type DNSContract struct {
	ABI abi.ABI
}

// NewDNSContract returns DNS contract struct
func NewDNSContract() (dnsContract DNSContract, err error) {
	var dnsABI abi.ABI
	dnsABI, err = abi.JSON(strings.NewReader(DNSContractABI))
	if err != nil {
		return
	}
	dnsContract.ABI = dnsABI
	return
}

// Register register name on diode network
func (dnsContract *DNSContract) Register(_name string, _record Address) (data []byte, err error) {
	data, err = dnsContract.ABI.Pack("Register", _name, _record)
	if err != nil {
		return
	}
	return
}

// DNSMetaKey returns storage key of Meta entry (destination, owner, name)
func DNSMetaKey(name string) []byte {
	key := crypto.Sha3Hash([]byte(name))
	index := util.IntToBytes(DNSNamesIndex)
	padIndex := util.PaddingBytesPrefix(index, 0, 32)
	padKey := util.PaddingBytesPrefix(key, 0, 32)
	return crypto.Sha3Hash(append(padKey, padIndex...))
}
