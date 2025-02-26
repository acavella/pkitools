package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/spf13/viper"
)

var appVersion = "0.0.0"
var appBuild = "UNK"
var appBuildDate = "00000000-0000"

func init() {

	viper.SetConfigName("config")  // name of config file (without extension)
	viper.SetConfigType("yaml")    // REQUIRED if the config file does not have the extension in the name
	viper.AddConfigPath("./conf/") // optionally look for config in the working directory

	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		fmt.Printf("fatal error config file: %s", err.Error())
	}

	printver()

}

func main() {
	// Define command line flag input
	subject := flag.String("cn", "default", "string, defines request common name.")
	rsaPtr := flag.Bool("rsa", false, "boolean, informs use of rsa cipher.")
	eccPtr := flag.Bool("ecc", false, "boolean, informs use of ecc cipher.")
	flag.Parse()

	// Parse command line flags

	keyUsage := viper.GetStringSlice("ku")
	exkeyUsage := viper.GetStringSlice("eku")

	fmt.Println("CN:", *subject)

	for i := 0; i < len(keyUsage); i++ {
		fmt.Printf("KU: %s\n", keyUsage[i])
	}

	for i := 0; i < len(keyUsage); i++ {
		fmt.Printf("EKU: %s\n", exkeyUsage[i])
	}

	if *rsaPtr {
		fmt.Println("Cipher: RSA")
		genrsa(*subject)
	} else if *eccPtr {
		fmt.Println("Cipher: ECC")
	} else {
		fmt.Println("Cipher spec was not defined.")
	}

}

type BasicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

func genrsa(subject string) {
	// Build RDN
	subj := pkix.Name{
		CommonName:   subject,
		Country:      []string{viper.GetString("dn.country")},
		Province:     []string{viper.GetString("dn.state")},
		Locality:     []string{viper.GetString("dn.city")},
		Organization: []string{viper.GetString("dn.org")},
	}
	rawSubj := subj.ToRDNSequence()
	asn1Subj, _ := asn1.Marshal(rawSubj)
	asn1Usage, _ := asn1.Marshal(BasicConstraints{false, -1})
	//asn1KeyUsage, _ := asn1.Marshal(x509.KeyUsage(4))
	//x509.ExtKeyUsageServerAuth
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		SignatureAlgorithm: x509.SHA384WithRSA,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier([]int{2, 5, 29, 19}),
				Critical: true,
				Value:    asn1Usage,
			},
			{
				Id:       asn1.ObjectIdentifier([]int{2, 5, 29, 15}),
				Critical: true,
				Value:    []byte{3, 2, 5, 160},
			},
			{
				Id:       asn1.ObjectIdentifier([]int{2, 5, 29, 37}),
				Critical: true,
				Value:    []byte{48, 10, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2},
			},
			{
				Id:       asn1.ObjectIdentifier([]int{2, 5, 29, 37}),
				Critical: true,
				Value:    []byte{48, 10, 6, 8, 43, 6, 1, 5, 5, 7, 3, 7},
			},
		},
	}
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, key)

	// Encode csr to PEM
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	// Write private key to file.
	if err := os.WriteFile("rsa.csr", csrPEM, 0755); err != nil {
		panic(err)
	}

	// Encode private key to PKCS#1 ASN.1 PEM.
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	// Write private key to file.
	if err := os.WriteFile("rsa.key", keyPEM, 0700); err != nil {
		panic(err)
	}
}

func printver() {
	fmt.Println("    ____  __ __ ______              __")
	fmt.Println("   / __ \/ //_//  _/ /_____  ____  / /____")
	fmt.Println("  / /_/ / ,<   / // __/ __ \/ __ \/ / ___/")
	fmt.Println(" / ____/ /| |_/ // /_/ /_/ / /_/ / (__  )") 
	fmt.Println("/_/   /_/ |_/___/\__/\____/\____/_/____/")
	fmt.Printf("GoRevoke ver. %s\n", appVersion)
	fmt.Printf("Build Type: %s\n", appBuild)
	fmt.Printf("Build Date: %s\n", appBuildDate)
}