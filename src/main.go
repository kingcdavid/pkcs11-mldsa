package main

import (
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"log"

	"github.com/kingcdavid/pkcs11"
)

func main() {
	// Path to your PKCS#11 library (.so/.dll)
	p := pkcs11.New("/usr/local/lib/softhsm/libsofthsm2.so")
	if p == nil {
		log.Fatal("Failed to load PKCS#11 library")
	}
	defer p.Destroy()

	err := p.Initialize()
	if err != nil {
		log.Fatalf("Initialize error: %v", err)
	}
	defer p.Finalize()

	// Find first slot with a token
	slots, err := p.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		log.Fatalf("No slots: %v", err)
	}
	slot := slots[0]

	// Open session and login
	session, err := p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		log.Fatalf("OpenSession error: %v", err)
	}
	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_USER, "1234")
	if err != nil {
		log.Fatalf("Login error: %v", err)
	}
	defer p.Logout(session)

	ckaID := make([]byte, 16)
	_, err = rand.Read(ckaID)
	if err != nil {
		log.Fatalf("Failed to generate random CKA_ID: %v", err)
	}

	// EC key pair templates (verify-only public, sign-only private)
	pubTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_PARAMETER_SET, pkcs11.CKP_ML_DSA_65),
		//pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_ML_DSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "mldsa-pub"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, ckaID),
	}
	privTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		//pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_ML_DSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "mldsa-priv"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, ckaID),
	}

	fmt.Print("Generating mech...\n")

	mech := pkcs11.NewMechanism(pkcs11.CKM_ML_DSA_KEY_PAIR_GEN, nil)

	fmt.Printf("Using mechanism: %+v\n", mech)

	fmt.Print("Generating key pair...\n")

	pubKey, privKey, err := p.GenerateKeyPair(
		session,
		[]*pkcs11.Mechanism{mech},
		pubTemplate,
		privTemplate,
	)
	if err != nil {
		log.Fatalf("GenerateKeyPair error: %v", err)
	}

	fmt.Printf("key pair created: pub=%v priv=%v\n", pubKey, privKey)

	attrs, err := p.GetAttributeValue(session, pubKey, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	})
	if err != nil {
		log.Fatalf("GetAttributeValue error: %v", err)
	}
	if len(attrs) == 0 || attrs[0] == nil || len(attrs[0].Value) == 0 {
		log.Fatalf("Attributes not available")
	}

	attrspub, err := p.GetAttributeValue(session, pubKey, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKP_ML_DSA_65, nil),
	})
	log.Printf("CKP_ML_DSA_65: %x", attrspub[0].Value)

	if err != nil {
		log.Fatalf("GetAttributeValue error: %v", err)
	}
	if len(attrs) == 0 || attrs[0] == nil || len(attrs[0].Value) == 0 {
		log.Fatalf("Attributes not available")
	}

	log.Printf("Public Key Attributes: %+v", attrspub)

	log.Printf("CKA_ID: %x", attrs[0].Value)
	log.Printf("CKA_LABEL: %s", attrs[1].Value)

	pointDER := attrs[2].Value

	var pemBytes = pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pointDER,
	})

	log.Printf("CKA_VALUE (PEM format):\n%s", pemBytes)

	digest := []byte("Hello, PKCS#11 ML DSA!")

	// Sign the digest using the private key
	err = p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ML_DSA, nil)}, privKey)
	if err != nil {
		log.Fatalf("SignInit error: %v", err)
	}

	signature, err := p.Sign(session, digest)
	if err != nil {
		log.Fatalf("Sign error: %v", err)
	}

	log.Printf("Signature (hex): %x", signature)

	// Verify the signature using the public key
	err = p.VerifyInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ML_DSA, nil)}, pubKey)
	if err != nil {
		log.Fatalf("VerifyInit error: %v", err)
	}

	err = p.Verify(session, digest, signature)
	if err != nil {
		log.Fatalf("Signature verification failed: %v", err)
	} else {
		log.Printf("Signature verification succeeded.")
	}
}
