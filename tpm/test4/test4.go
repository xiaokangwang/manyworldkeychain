package main

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"github.com/canonical/go-tpm2"
	"os"
)

func main() {
	var err error
	tpmCtx, err := tpm2.NewTPMContext(nil)
	if err != nil {
		panic(err)
	}
	key := []byte(os.Args[2])

	tomac := []byte(os.Args[1])


	hmackey := sha512.Sum512_256(key)

	hmacexec := tpm2.Public{
		Type:       tpm2.ObjectTypeKeyedHash,
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign,
		Params:     &tpm2.PublicParamsU{KeyedHashDetail: &tpm2.KeyedHashParams{Scheme: tpm2.KeyedHashScheme{
			Scheme:  tpm2.KeyedHashSchemeHMAC,
			Details: &tpm2.SchemeKeyedHashU{HMAC: &tpm2.SchemeHMAC{HashAlg: tpm2.HashAlgorithmSHA256}},
		}}},
		Unique:     &tpm2.PublicIDU{KeyedHash: hmackey[:]},
	}

	primObjCtx, public, _, _, _, err := tpmCtx.CreatePrimary(tpmCtx.OwnerHandleContext(), nil, &hmacexec, nil, nil , nil)
	if err != nil {
		panic(err)
	}
	fmt.Println("TPM HMac Key Fingerprint: ",hex.EncodeToString(public.Unique.KeyedHash))
	var result tpm2.Digest

	err = tpmCtx.RunCommand(tpm2.CommandHMAC,nil, tpm2.ResourceContextWithSession{Context: primObjCtx, Session: nil}, tpm2.Delimiter,
		tpm2.MaxBuffer(tomac), tpm2.HashAlgorithmSHA256, tpm2.Delimiter, tpm2.Delimiter, &result)

	if err != nil {
		panic(err)
	}

	println(hex.EncodeToString(result))

	err = tpmCtx.FlushContext(primObjCtx)

	if err != nil {
		panic(err)
	}

}
