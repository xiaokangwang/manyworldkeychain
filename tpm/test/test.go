package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"io/ioutil"
)

func main() {
	var err error
	tpmCtx, err := tpm2.NewTPMContext(nil)
	if err != nil {
		panic(err)
	}
	primary := tpm2.Public{
		Type:       tpm2.ObjectTypeECC,
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
		Params:     &tpm2.PublicParamsU{ECCDetail: &tpm2.ECCParams{
			Symmetric: tpm2.SymDefObject{
				Algorithm: tpm2.SymObjectAlgorithmAES,
				KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
				Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}},
			Scheme:    tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
			CurveID:   tpm2.ECCCurveNIST_P256,
			KDF:       tpm2.KDFScheme{Scheme:tpm2.KDFAlgorithmNull, Details: &tpm2.KDFSchemeU{
			}},
		}},
		Unique:     &tpm2.PublicIDU{ECC: new(tpm2.ECCPoint)},
	}

	_ = primary

	template := tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs: tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrNoDA | tpm2.AttrRestricted | tpm2.AttrDecrypt,
		Params: &tpm2.PublicParamsU{
			RSADetail: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{
					Algorithm: tpm2.SymObjectAlgorithmAES,
					KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
					Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}},
				Scheme:   tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
				KeyBits:  2048,
				Exponent: 0}},
		Unique: &tpm2.PublicIDU{RSA: make(tpm2.PublicKeyRSA, 256)}}

	_ = template

	primObjCtx, public, _, _, _, err := tpmCtx.CreatePrimary(tpmCtx.OwnerHandleContext(), nil, &primary, nil, nil , nil)
	if err != nil {
		panic(err)
	}
	_ = primObjCtx
	println(primObjCtx.Handle().String())

	bytesw, err := mu.MarshalToBytes(public)
	if err != nil {
		panic(err)
	}
	ioutil.WriteFile("prim.u", bytesw, 0666)

	hmacexec := tpm2.Public{
		Type:       tpm2.ObjectTypeKeyedHash,
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign,
		Params:     &tpm2.PublicParamsU{KeyedHashDetail: &tpm2.KeyedHashParams{Scheme: tpm2.KeyedHashScheme{
			Scheme:  tpm2.KeyedHashSchemeHMAC,
			Details: &tpm2.SchemeKeyedHashU{HMAC: &tpm2.SchemeHMAC{HashAlg: tpm2.HashAlgorithmSHA256}},
		}}},
		Unique:     &tpm2.PublicIDU{KeyedHash: make(tpm2.Digest,32)},
	}

	_ = hmacexec

	priv, pub, _, _, _, err := tpmCtx.Create(primObjCtx, nil, &hmacexec,nil,nil,nil)
	if err != nil {
		panic(err)
	}
	{
		bytes, err := mu.MarshalToBytes(priv)
		if err != nil {
			panic(err)
		}
		ioutil.WriteFile("hmac.cr", bytes, 0666)
		ioutil.WriteFile("hmac.r", priv, 0666)

	}
	{
		bytes2, err := mu.MarshalToBytes(pub)
		if err != nil {
			panic(err)
		}
		ioutil.WriteFile("hmac.u", bytes2, 0666)
		buf := bytes.NewBuffer(nil)
		binary.Write(buf, binary.BigEndian,uint16(len(bytes2)))
		buf.Write(bytes2)
		ioutil.WriteFile("hmac.cu", buf.Bytes(), 0666)
	}

	rsctx, err := tpmCtx.Load(primObjCtx,priv,pub,nil)
	if err != nil {
		panic(err)
	}

	{
		hmacu , err := ioutil.ReadFile("hmac.u")
		if err != nil {
			panic(err)
		}
		var hmacpub tpm2.Public
		_ , err = mu.UnmarshalFromBytes(hmacu, &hmacpub)
		if err != nil {
			panic(err)
		}
		hmacr , err := ioutil.ReadFile("hmac.r")
		if err != nil {
			panic(err)
		}
		fmt.Println(bytes.Equal(hmacr, priv))
	}

	err = tpmCtx.FlushContext(rsctx)
	if err != nil {
		panic(err)
	}

	err = tpmCtx.FlushContext(primObjCtx)
	if err != nil {
		panic(err)
	}

}
