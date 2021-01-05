package main

import (
	"encoding/hex"
	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"io/ioutil"
	"os"
)

func main() {
	var err error
	tpmCtx, err := tpm2.NewTPMContext(nil)
	if err != nil {
		panic(err)
	}
	primu , err := ioutil.ReadFile("prim.u")
	if err != nil {
		panic(err)
	}
	var primpub tpm2.Public
	_ , err = mu.UnmarshalFromBytes(primu, &primpub)
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

	primObjCtx, _, _, _, _, err := tpmCtx.CreatePrimary(tpmCtx.OwnerHandleContext(), nil, &primary, nil, nil , nil)
	if err != nil {
		panic(err)
	}
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

	//Discard Device generated content
	//hmacpub.Unique = nil
	//a , _ := hmacpub.Name()
	//println(hex.EncodeToString(a.Digest()))
	hmacctx, err := tpmCtx.Load(primObjCtx,hmacr,&hmacpub ,nil)


	if err != nil {
		panic(err)
	}

	tomac := []byte(os.Args[1])

	var result tpm2.Digest

	err = tpmCtx.RunCommand(tpm2.CommandHMAC,nil, tpm2.ResourceContextWithSession{Context: hmacctx, Session: nil}, tpm2.Delimiter,
		tpm2.MaxBuffer(tomac), tpm2.HashAlgorithmSHA256, tpm2.Delimiter, tpm2.Delimiter, &result)

	if err != nil {
		panic(err)
	}

	/*
	hmacseq , err := tpmCtx.HMACStart(hmacctx, nil , tpm2.HashAlgorithmNull , nil )
	if err != nil {
		panic(err)
	}
	ret, _, err := tpmCtx.SequenceExecute(hmacseq, []byte(os.Args[1]),0,nil,nil)
	if err != nil {
		panic(err)
	}*/
	println(hex.EncodeToString(result))

	tpmCtx.FlushContext(hmacctx)
	tpmCtx.FlushContext(primObjCtx)
}
