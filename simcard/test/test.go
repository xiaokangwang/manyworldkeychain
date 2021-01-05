package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/sf1/go-card/smartcard"
	"github.com/yerden/go-util/bcd"
	"os"
)

func main() {
	ctx , err := smartcard.EstablishContext()
	if err != nil {
		panic(err)
	}
	cardreader, err := ctx.WaitForCardPresent()
	if err != nil {
		panic(err)
	}
	card, err := cardreader.Connect()
	if err != nil {
		panic(err)
	}

	{
		selectgsm := smartcard.Command3(0xa0,0xa4, 0x00, 0x00 , []byte{0x3F,0x00})
		resp, err := card.TransmitAPDU(selectgsm)
		if err != nil {
			panic(err)
		}
		if resp.SW1() != 0x9f {
			panic(resp.String())
		}
		readgsm := smartcard.Command2(0xa0,0xC0, 0x00, 0x00 , resp.SW2())
		respreadgsm, err := card.TransmitAPDU(readgsm)
		if err != nil {
			panic(err)
		}
		if respreadgsm.SW1() != 0x90 {
			panic(respreadgsm.String())
		}
	}

	{
		selectgsm := smartcard.Command3(0xa0,0xa4, 0x00, 0x00 , []byte{0x2F,0xE2})
		resp, err := card.TransmitAPDU(selectgsm)
		if err != nil {
			panic(err)
		}
		if resp.SW1() != 0x9f {
			panic(resp.String())
		}
		readgsm := smartcard.Command2(0xa0,0xC0, 0x00, 0x00 , resp.SW2())
		respreadgsm, err := card.TransmitAPDU(readgsm)
		if err != nil {
			panic(err)
		}
		if respreadgsm.SW1() != 0x90 {
			panic(respreadgsm.String())
		}
	}

	{

		readselectimei := smartcard.Command2(0xa0,0xb0, 0x00, 0x00 , 0x0A)
		respselectimeiread, err := card.TransmitAPDU(readselectimei)
		if err != nil {
			panic(err)
		}
		if respselectimeiread.SW1() != 0x90 {
			panic(respselectimeiread.String())
		}
		//fmt.Println(hex.EncodeToString(respselectimeiread.Data()))
		bcddecoder := bcd.NewDecoder(bcd.Telephony)
		decodebuf := make([]byte, 64)
		n , err := bcddecoder.Decode(decodebuf, respselectimeiread.Data()[:])
		if err != nil {
			panic(err)
		}
		fmt.Println(string(decodebuf[:n]))

	}

	{
		selectgsm := smartcard.Command3(0xa0,0xa4, 0x00, 0x00 , []byte{0x7f,0x20})
		resp, err := card.TransmitAPDU(selectgsm)
		if err != nil {
			panic(err)
		}
		if resp.SW1() != 0x9f {
			panic(resp.String())
		}
		readgsm := smartcard.Command2(0xa0,0xC0, 0x00, 0x00 , resp.SW2())
		respreadgsm, err := card.TransmitAPDU(readgsm)
		if err != nil {
			panic(err)
		}
		if respreadgsm.SW1() != 0x90 {
			panic(respreadgsm.String())
		}
	}


	{
		selectimei := smartcard.Command3(0xa0,0xa4, 0x00, 0x00 , []byte{0x6f,0x07})
		respselectimei, err := card.TransmitAPDU(selectimei)
		if err != nil {
			panic(err)
		}
		if respselectimei.SW1() != 0x9f {
			panic(respselectimei.String())
		}
		readselectimei := smartcard.Command2(0xa0,0xC0, 0x00, 0x00 , respselectimei.SW2())
		respselectimeiread, err := card.TransmitAPDU(readselectimei)
		if err != nil {
			panic(err)
		}
		if respselectimeiread.SW1() != 0x90 {
			panic(respselectimeiread.String())
		}
	}


	{

		readselectimei := smartcard.Command2(0xa0,0xb0, 0x00, 0x00 , 0x09)
		respselectimeiread, err := card.TransmitAPDU(readselectimei)
		if err != nil {
			panic(err)
		}
		if respselectimeiread.SW1() != 0x90 {
			panic(respselectimeiread.String())
		}
		//fmt.Println(hex.EncodeToString(respselectimeiread.Data()))
		bcddecoder := bcd.NewDecoder(bcd.Telephony)
		decodebuf := make([]byte, 64)
		n , err := bcddecoder.Decode(decodebuf, respselectimeiread.Data()[1:])
		if err != nil {
			panic(err)
		}
		fmt.Println(string(decodebuf[:n])[1:])

	}


	{
		key := []byte(os.Args[1])
		hmackey := sha256.Sum256(key)

		readgsmal := smartcard.Command3(0xa0,0x88, 0x00, 0x00 , hmackey[:16])
		respreadgsmal, err := card.TransmitAPDU(readgsmal)
		if err != nil {
			panic(err)
		}
		if respreadgsmal.SW1() != 0x9f {
			panic(respreadgsmal.String())
		}

		readgsmald := smartcard.Command2(0xa0,0xC0, 0x00, 0x00 , respreadgsmal.SW2())
		respgsmald, err := card.TransmitAPDU(readgsmald)
		if err != nil {
			panic(err)
		}
		if respgsmald.SW1() != 0x90 {
			panic(respgsmald.String())
		}
		println(hex.EncodeToString(respgsmald.Data()))
	}


}
