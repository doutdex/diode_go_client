// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/diodechain/diode_go_client/accounts/abi"
	"github.com/diodechain/diode_go_client/crypto"
	"github.com/diodechain/diode_go_client/crypto/secp256k1"
	"io"
	"sync"
)

type MockMsg struct {
	Ephemeral []byte
	HostKey   []byte
	Signature []byte
}

// temporary test file for ecdh
func main() {
	// ssh ecdh client first step, send client public key to server
	// implement with golang ssh
	var wg sync.WaitGroup
	clientPriv, err := generateSecp256k1Key(rand.Reader)
	if err != nil {
		panic(err.Error())
	}
	clientPubBytes := crypto.MarshalPubkey(&clientPriv.PublicKey)
	// client should wait for the response
	// what server should do
	// unmarshal client public key
	uClientPubKey, err := crypto.UnmarshalPubkey(clientPubBytes)
	if err != nil {
		panic(err.Error())
	}
	// wait server return
	wc := make(chan MockMsg, 1)
	wg.Add(1)
	go func() {
		res := <-wc
		uuServerEphPubKey, err := crypto.UnmarshalPubkey(res.Ephemeral)
		if err != nil {
			panic(err.Error())
		}
		// verify signature
		cSecret, _ := crypto.S256().ScalarMult(uuServerEphPubKey.X, uuServerEphPubKey.Y, clientPriv.D.Bytes())
		// turn secret to u256
		uCSecret := abi.U256(cSecret)
		fmt.Println("Client secret: ", uCSecret)
		// [server public key | client public key | ephemeral public key | ucsecret]
		h := sha256.New()
		h.Write(res.HostKey)
		h.Write(clientPubBytes)
		h.Write(res.Ephemeral)
		h.Write(uCSecret.Bytes())
		HH := h.Sum(nil)
		fmt.Println("Client hash: ", HH)
		sigg := res.Signature[1:]
		isValid := secp256k1.VerifySignature(res.HostKey, HH, sigg)
		fmt.Println("Signature validation result: ", isValid)
		wg.Done()
	}()
	serverPriv, err := generateSecp256k1Key(rand.Reader)
	if err != nil {
		panic(err.Error())
	}
	serverPubBytes := crypto.MarshalPubkey(&serverPriv.PublicKey)
	// server eph private key
	ephPriv, err := generateSecp256k1Key(rand.Reader)
	if err != nil {
		panic(err.Error())
	}
	ephPubBytes := crypto.MarshalPubkey(&ephPriv.PublicKey)
	// compute shared secret
	secret, _ := crypto.S256().ScalarMult(uClientPubKey.X, uClientPubKey.Y, ephPriv.D.Bytes())
	// turn secret to u256
	uSecret := abi.U256(secret)
	fmt.Println("Sever secret: ", uSecret)
	// making hash and sign from server private key
	// [server public key | client public key | ephemeral public key | usecret]
	h := sha256.New()
	h.Write(serverPubBytes)
	h.Write(clientPubBytes)
	h.Write(ephPubBytes)
	h.Write(uSecret.Bytes())
	H := h.Sum(nil)
	fmt.Println("Server hash: ", H)
	sig, err := secp256k1.Sign(H, serverPriv.D.Bytes())
	if err != nil {
		panic(err.Error())
	}
	msg := MockMsg{
		Ephemeral: ephPubBytes,
		HostKey:   serverPubBytes,
		Signature: sig,
	}
	wc <- msg
	wg.Wait()
}

func generateSecp256k1Key(rand io.Reader) (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(secp256k1.S256(), rand)
}
