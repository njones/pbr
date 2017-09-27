package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"text/template"
	"time"
)

var binVersion = "0.1.0"
var binBuildDate = "27 Sep 2017"

func main() {
	var (
		err     error
		output  = flag.String("out", "", "An output file, if empty stdout is used.")
		version = flag.Bool("version", false, "Display the current version.")
	)

	flag.Parse()

	if *version {
		fmt.Println("PEM Block Reader %s %s", binVersion, binBuildDate)
		os.Exit(0)
	}

	if len(flag.Args()) == 0 {
		log.Fatal("need a valid input .pem file as the first argument.")
	}

	o := os.Stdout
	if len(*output) > 0 {
		o, err = os.Create(*output)
		if err != nil {
			log.Fatalf("creating file: %v", err)
		}
	}

	f, err := os.Open(flag.Args()[0])
	if err != nil {
		log.Fatalf("opening file: %v", err)
	}
	defer f.Close()

	parse(f, o)
}

func parse(in io.Reader, out io.Writer) {
	var err error
	var rest []byte

	tf := NewTplFuncs()
	funcMap := template.FuncMap{
		"cert":               tf.Cert,
		"version":            tf.Version,
		"serialNumber":       tf.SerialNumber,
		"signatureAlgorithm": tf.SignatureAlgorithm,
		"issuer":             tf.Issuer,
		"subject":            tf.Subject,
		"pkAlgorithm":        tf.PublicKeyAlgorithm,
		"pk":                 tf.PublicKey,
		"pkModulus":          tf.PublicKeyModulus,
		"pkExponent":         tf.PublicKeyExponent,
		"signatureModulus":   tf.SignatureModulus,
		"extensionsLabel":    tf.ExtensionsLabel,
		"extensionsDisplay":  tf.tplExtensionsDisplay,

		"fmtTime": func(t time.Time) string {
			loc, err := time.LoadLocation("Etc/GMT")
			if err != nil {
				log.Fatalf("time location: %v", err)
			}
			return t.In(loc).Format("Jan _2 15:04:05 2006 MST")
		},
	}

	pemTypeMap := map[string]func(*pem.Block){
		"CERTIFICATE REQUEST": func(block *pem.Block) {
			crts, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				log.Fatalf("parse template: %v", err)
			}

			tfr := NewTplFuncs(WithBlockType(block.Type))
			funcReqMap := template.FuncMap{
				"cert":       tfr.CertReq,
				"version":    tfr.Version,
				"pk":         tfr.PublicKey,
				"pkModulus":  tfr.PublicKeyModulus,
				"pkExponent": tfr.PublicKeyExponent,
			}

			t := template.Must(template.New("certificate-request.tmpl").
				Funcs(funcMap).
				Funcs(funcReqMap).
				Parse(certReqTmpl))
			err = t.Execute(out, crts)
			if err != nil {
				log.Fatalf("execute template: %s %#v", err, t)
			}
		},
		"PRIVATE KEY": func(block *pem.Block) {
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				log.Fatalf("parse private key %v", err)
			}

			pKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				log.Fatalf("key is of type %T and not  *rsa.PrivateKey", key)
			}

			pkBytes := pKey.PublicKey.N.Bytes()
			if err != nil {
				log.Fatalf("parse private key hex %v", err)
			}
			mln := multilnFingerprint("          ", modLenPublicKey, pkBytes, "00")
			fmt.Fprintln(out, "Private Key:")
			fmt.Fprintf(out, "Modulus (%d bit):\n%s\n", len(pkBytes)*8, mln)
		},
		"RSA PRIVATE KEY": func(block *pem.Block) {
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				log.Fatalf("parse private key %v", err)
			}

			pkBytes := key.PublicKey.N.Bytes()
			mln := multilnFingerprint("          ", modLenPublicKey, pkBytes, "00")
			fmt.Fprintln(out, "Private Key:")
			fmt.Fprintf(out, "Modulus (%d bit):\n%s\n", len(pkBytes)*8, mln)
		},
		"CERTIFICATE": func(block *pem.Block) {
			crts, err := x509.ParseCertificates(block.Bytes)
			if err != nil {
				log.Fatalf("parse template: %v", err)
			}

			t := template.Must(template.New("certificate.tmpl").Funcs(funcMap).Parse(certTmpl))
			err = t.Execute(out, crts)
			if err != nil {
				log.Fatalf("execute template: %v", err)
			}
		},
	}

	rest, err = ioutil.ReadAll(in)
	if err != nil {
		log.Fatalf("reading in file: %v", err)
	}

	for i := 0; len(rest) > 0; i++ {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		fn, ok := pemTypeMap[block.Type]
		if !ok {
			// if we don't know the type then print out raw data
			fmt.Fprintf(out, "%#v\n", block)
			continue
		}
		fn(block)
		if len(rest) > 0 {
			fmt.Fprintln(out, strings.Repeat("-", 65)) // the line break between blocks
		}
	}
	fmt.Fprintln(out, "done.")
}

var certTmpl = `{{- range . -}}{{- cert . -}}
Certificate:
    Data:
        {{ version .Version }}
        {{ serialNumber .SerialNumber }}
        {{ signatureAlgorithm .SignatureAlgorithm }}
        {{ issuer .Issuer }}
        Validity
            Not Before: {{ fmtTime .NotBefore }}
            Not After : {{ fmtTime .NotAfter }}
        {{ subject .Subject }}
        Subject Public Key Info:
            {{ pkAlgorithm .PublicKeyAlgorithm }}
            {{ pk .PublicKey }}
                {{ pkModulus }}
                {{ pkExponent }}
        {{- extensionsLabel .Extensions -}}
            {{ range .Extensions }}
                {{- extensionsDisplay . -}}
            {{ end }}
    {{ signatureAlgorithm .SignatureAlgorithm }}
        {{- signatureModulus .Signature -}}
{{ end }}
`
var certReqTmpl = `{{- cert . -}}
Certificate Request:
    Data:
        {{ version .Version }}
        {{ subject .Subject }}
        Subject Public Key Info:
            {{ pkAlgorithm .PublicKeyAlgorithm }}
                {{ pk .PublicKey }}
                {{ pkModulus }}
                {{ pkExponent }}
        Attributes:
            a0:00
    {{ signatureAlgorithm .SignatureAlgorithm }}
        {{- signatureModulus .Signature }}
`
