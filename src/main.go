package main

import (
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

	// ML-DSA key pair templates (verify-only public, sign-only private)
	pubTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		// Required by many tokens
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_ML_DSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		// Optional but recommended identifiers
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "mldsa-pub"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte{0x01}),
	}
	privTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		// Keep type consistent on the private key as well
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_ML_DSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		// Common hardening
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "mldsa-priv"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte{0x01}),
	}

	// Provide ML-DSA parameter set via mechanism parameter (choose 44, 65, or 87)
	mldsaparams := uint(65)
	pubKey, privKey, err := p.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ML_DSA_KEY_PAIR_GEN, mldsaparams)},
		pubTemplate, privTemplate)
	if err != nil {
		log.Fatalf("GenerateKeyPair error: %v", err)
	}

	fmt.Printf("ML-DSA key pair created: pub=%v priv=%v\n", pubKey, privKey)
}
