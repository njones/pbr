package main

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"log"
	"math/big"
	"strings"
)

const (
	maxLen          = 129
	modLenPublicKey = 45
	modLenSignature = 54
)

var (
	nameParts  = []string{"C", "ST", "L", "O", "OU", "CN"}
	policyOIDs = map[string]string{
		// Policy Id
		"2.23.140.1.2.2": "⊙",

		// Policy Types
		"1.3.6.1.5.5.7.2.1": "CPS",
		"1.3.6.1.5.5.7.2.2": "User Notice",
	}
	signingAlgo = map[x509.SignatureAlgorithm]string{
		x509.MD2WithRSA:      "md2WithRSAEncryption",
		x509.MD5WithRSA:      "md5WithRSAEncryption",
		x509.SHA1WithRSA:     "sha1WithRSAEncryption",
		x509.SHA256WithRSA:   "sha256WithRSAEncryption",
		x509.SHA384WithRSA:   "sha384WithRSAEncryption",
		x509.SHA512WithRSA:   "sha512WithRSAEncryption",
		x509.DSAWithSHA1:     "dsaWithSHA1Encryption",
		x509.DSAWithSHA256:   "dsaWithSHA256Encryption",
		x509.ECDSAWithSHA1:   "ecdsaWithSHA1Encryption",
		x509.ECDSAWithSHA256: "ecdsaWithSHA256Encryption",
		x509.ECDSAWithSHA384: "ecdsaWithSHA384Encryption",
		x509.ECDSAWithSHA512: "ecdsaWithSHA512Encryption",
	}
	extKeyUsage = map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:                        "ExtKeyUsageAny",
		x509.ExtKeyUsageServerAuth:                 "TLS Web Server Authentication",
		x509.ExtKeyUsageClientAuth:                 "TLS Web Client Authentication",
		x509.ExtKeyUsageCodeSigning:                "ExtKeyUsageCodeSigning",
		x509.ExtKeyUsageEmailProtection:            "ExtKeyUsageEmailProtection",
		x509.ExtKeyUsageIPSECEndSystem:             "ExtKeyUsageIPSECEndSystem",
		x509.ExtKeyUsageIPSECTunnel:                "ExtKeyUsageIPSECTunnel",
		x509.ExtKeyUsageIPSECUser:                  "ExtKeyUsageIPSECUser",
		x509.ExtKeyUsageTimeStamping:               "ExtKeyUsageTimeStamping",
		x509.ExtKeyUsageOCSPSigning:                "ExtKeyUsageOCSPSigning",
		x509.ExtKeyUsageMicrosoftServerGatedCrypto: "ExtKeyUsageMicrosoftServerGatedCrypto",
		x509.ExtKeyUsageNetscapeServerGatedCrypto:  "ExtKeyUsageNetscapeServerGatedCrypto",
	}
	pubKeyAlgo = map[x509.PublicKeyAlgorithm]string{
		x509.RSA:   "rsaEncryption",
		x509.DSA:   "dsaEncryption",
		x509.ECDSA: "ecdsaEncryption",
	}
)

type (
	IA5 struct {
		s string
	}

	TF8 struct {
		s []string
	}
)

func (s *IA5) String() string {
	return " " + s.s
}

func (s *TF8) String() string {
	for i, v := range s.s {
		s.s[i] = "                    Explicit Text: " + v
	}
	return "\n" + strings.Join(s.s, "\n")
}

func rawWrap(s string, wLen int) (r string) {
	var ss []string
	lines := int(len(s) / wLen)
	for i := 0; i <= lines; i++ {
		start, end := i*wLen, (i*wLen)+wLen
		if i < lines {
			ss = append(ss, s[start:end])
		} else {
			ss = append(ss, s[start:])
		}
	}
	return strings.Join(ss, "\n")
}

func eqName(n pkix.Name) (r string) {
	var ss []string
	var m = map[string]string{
		"C":  strings.Join(n.Country, ","),
		"ST": strings.Join(n.Province, ","),
		"L":  strings.Join(n.Locality, ","),
		"O":  strings.Join(n.Organization, ","),
		"OU": strings.Join(n.OrganizationalUnit, ","),
		"CN": n.CommonName,
	}

	for _, v := range n.Names {
		if v.Type.String() == "1.2.840.113549.1.9.1" {
			m["CN"] += "/emailAddress=" + v.Value.(string)
		}
	}

	for _, v := range nameParts {
		if len(m[v]) > 0 {
			ss = append(ss, v+"="+m[v])
		}
	}
	return strings.Join(ss, ", ")
}

func multilnFingerprint(lnLead string, lnWidth int, b []byte, pad string) (r string) {
	out := strings.Join(strings.Split(strings.TrimSpace(fmt.Sprintf("%s% x", pad+" ", b)), " "), ":")
	trailNL := "\n"
	for len(out) > 0 {
		var ln string
		if len(out) < lnWidth {
			lnWidth = len(out)
			trailNL = ""
		}
		ln, out = out[:lnWidth], out[lnWidth:]
		r += fmt.Sprintf("%s%s%s", lnLead, ln, trailNL)
	}
	return r
}

func inSlice(s string, ss []string) bool {
	for _, v := range ss {
		if s == v {
			return true
		}
	}
	return false
}

type tplFuncs struct {
	blockType struct {
		isCertificateRequest bool
	}
	version int
	in      map[int]string

	policy []*struct {
		id string
		mv map[string]interface{} // keeps the key strings
		ss []string               // Keeps the keys in order
	}
	pk struct {
		name     string
		bytes    []byte
		exponent int
	}

	certs    []*x509.Certificate
	certReqs []*x509.CertificateRequest
}

type tplOptFuncsFunc func(*tplFuncs)

func NewTplFuncs(opts ...tplOptFuncsFunc) *tplFuncs {
	tf := new(tplFuncs)
	tf.in = make(map[int]string)
	for _, opt := range opts {
		opt(tf)
	}
	return tf
}

func WithBlockType(s string) tplOptFuncsFunc {
	return func(tf *tplFuncs) {
		tf.blockType.isCertificateRequest = s == "CERTIFICATE REQUEST"
	}
}

func (tf *tplFuncs) indent(i int) (r string) {
	var ok bool
	if r, ok = tf.in[i]; !ok {
		tf.in[i] = strings.Repeat("  ", i)
		r = tf.in[i]
	}
	return r
}

func (tf *tplFuncs) RawExtension(pe pkix.Extension) (r string) {
	var rv asn1.RawValue
	var ss []string

	_, err := asn1.Unmarshal(pe.Value, &rv)
	if err != nil {
		log.Fatalf("extension unmarshal: %v", err)
	}

	var start int
	var stripLead bool
	for i, v := range rv.Bytes {
		if v == 13 && !stripLead {
			stripLead = true
			start = i + 1
		}
		if v < 32 || v > 126 {
			v = '.'
		}
		ss = append(ss, string(v))
	}
	return rawWrap(strings.Join(ss, "")[start:], maxLen)
}

func (tf *tplFuncs) Policy(idx int, pe pkix.Extension) (r string) {
	var ss []string

	tf.loop(idx, "", pe.Value)

	for _, v := range tf.policy[idx].ss {
		if d, ok := tf.policy[idx].mv[v]; ok {
			ss = append(ss, fmt.Sprintf("%s%s:%s", tf.indent(9), policyOIDs[v], d))
		}
	}

	return fmt.Sprintf("%sPolicy: %s\n%s\n", tf.indent(8), tf.policy[idx].id, strings.Join(ss, "\n"))
}

func (tf *tplFuncs) loop(k int, keyId string, b []byte) (e error) {
	var raw asn1.RawValue

	for len(b) > 0 {
		if b, e = asn1.Unmarshal(b, &raw); e != nil {
			return e
		}

		switch raw.Class {
		case asn1.ClassUniversal:
			switch raw.Tag {
			case asn1.TagSequence:
				if e = tf.loop(k, keyId, raw.Bytes); e != nil {
					return e
				}
			case asn1.TagOID:
				var oid asn1.ObjectIdentifier
				if _, e = asn1.Unmarshal(raw.FullBytes, &oid); e != nil {
					return e
				}

				if v, ok := policyOIDs[oid.String()]; ok {
					if v == "⊙" {
						tf.policy[k].id = oid.String()
					} else {
						keyId = oid.String()
						if !inSlice(keyId, tf.policy[k].ss) {
							tf.policy[k].ss = append(tf.policy[k].ss, keyId)
						}
					}
				}
			case asn1.TagIA5String:
				if keyId != "" {
					tf.policy[k].mv[keyId] = &IA5{string(raw.Bytes)}
				}
			case asn1.TagUTF8String:
				if keyId != "" {
					if mvps, ok := tf.policy[k].mv[keyId]; ok {
						mvps.(*TF8).s = append(mvps.(*TF8).s, string(raw.Bytes))
					} else {
						tf.policy[k].mv[keyId] = &TF8{[]string{string(raw.Bytes)}}
					}
				}
			default:
				// Skip
			}
		case asn1.ClassContextSpecific:
			// Skip
		}
	}

	return nil
}

func (tf *tplFuncs) Cert(c *x509.Certificate) (r string) {
	var p struct {
		id string
		mv map[string]interface{}
		ss []string
	}
	p.mv = make(map[string]interface{})
	tf.certs = append(tf.certs, c)
	tf.policy = append(tf.policy, &p)
	return
}

func (tf *tplFuncs) CertReq(c *x509.CertificateRequest) (r string) {
	var p struct {
		id string
		mv map[string]interface{}
		ss []string
	}
	p.mv = make(map[string]interface{})
	tf.certReqs = append(tf.certReqs, c)
	tf.policy = append(tf.policy, &p)
	return
}

func (tf *tplFuncs) Version(i int) (r string) {
	tf.version = i
	n := i - 1
	if tf.blockType.isCertificateRequest {
		n = i
	}
	return fmt.Sprintf("Version: %d (%#x)", i, n)
}

func (tf *tplFuncs) SerialNumber(i *big.Int) (r string) {
	switch tf.version {
	case 1:
		r = "Serial Number: " + fmt.Sprintf("%d (%#x)", i, i.Bytes())
	case 2:
		r = "Serial Number: " + fmt.Sprintf("%d (%#x)", i, i.Bytes())
	case 3:
		r = fmt.Sprintf("Serial Number:\n%s%s", tf.indent(6), strings.Join(strings.Split(fmt.Sprintf("% x", i.Bytes()), " "), ":"))
	default:
		r = "[unknown version]"
	}
	return r
}

func (tf *tplFuncs) SignatureAlgorithm(a x509.SignatureAlgorithm) (r string) {
	var ok bool
	if r, ok = signingAlgo[a]; !ok {
		r = "[unknown algorithm]"
	}
	return "Signature Algorithm: " + r
}

func (tf *tplFuncs) Issuer(n pkix.Name) (r string) {
	return "Issuer: " + eqName(n)
}

func (tf *tplFuncs) Subject(n pkix.Name) (r string) {
	return "Subject: " + eqName(n)
}

func (tf *tplFuncs) PublicKeyAlgorithm(pka x509.PublicKeyAlgorithm) (r string) {
	var ok bool

	if r, ok = pubKeyAlgo[pka]; !ok {
		r = "unknownPublicKeyAlgorithm"
	}

	return "Public Key Algorithm: " + r
}

func (tf *tplFuncs) PublicKey(pk interface{}) (r string) {
	switch pk := pk.(type) {
	case *rsa.PublicKey:
		tf.pk.name = "RSA"
		tf.pk.exponent = pk.E
		tf.pk.bytes = pk.N.Bytes()
	case *dsa.PublicKey:
		tf.pk.name = "DSA"
		tf.pk.bytes = pk.Y.Bytes()
	case *ecdsa.PublicKey:
		tf.pk.name = "[unsupported]"
	default:
		tf.pk.name = "[unknown]"
	}
	if tf.blockType.isCertificateRequest {
		return fmt.Sprintf("Public-Key: (%d bit)", len(tf.pk.bytes)*8)
	}
	return fmt.Sprintf("%s Public Key: (%d bit)", tf.pk.name, len(tf.pk.bytes)*8)
}

func (tf *tplFuncs) PublicKeyModulus() (r string) {
	mln := multilnFingerprint(tf.indent(10), modLenPublicKey, tf.pk.bytes, "00")
	if tf.blockType.isCertificateRequest {
		return fmt.Sprintf("Modulus:\n%s", mln)
	}
	return fmt.Sprintf("Modulus (%d bit):\n%s", len(tf.pk.bytes)*8, mln)
}

func (tf *tplFuncs) PublicKeyExponent() (r string) {
	return fmt.Sprintf("Exponent: %d (0x10001)", tf.pk.exponent)
}

func (tf *tplFuncs) SignatureModulus(b []byte) (r string) {
	return "\n" + multilnFingerprint(tf.indent(4), modLenSignature, b, "")
}

func (tf *tplFuncs) ExtensionsLabel(pe *[]pkix.Extension) (r string) {
	if len(*pe) > 0 {
		r = fmt.Sprintf("\n%sX509v3 extensions:", tf.indent(4)) // becuase the newlines are collapsed in the template
	}
	return r
}

func (tf *tplFuncs) tplExtensionsDisplay(pe pkix.Extension) (r string) {
	var ln, isCriticalText string
	if pe.Critical {
		isCriticalText = " critical"
	}

	cIdx := len(tf.certs) - 1
	cert := tf.certs[cIdx]

	switch pe.Id.String() {
	case "2.5.29.17":
		r = "X509v3 Subject Alternative Name:"
		if len(cert.DNSNames) > 0 {
			label := fmt.Sprintf("%sDNS:", tf.indent(8))
			ln += label + strings.Join(cert.DNSNames, "\n"+label)
		}
		if len(cert.EmailAddresses) > 0 {
			label := fmt.Sprintf("%sEMAIL:", tf.indent(8))
			ln += label + strings.Join(cert.EmailAddresses, "\n"+label)
		}
		if len(cert.IPAddresses) > 0 {
			var ss []string
			for _, v := range cert.IPAddresses {
				ss = append(ss, v.String())
			}
			label := fmt.Sprintf("%sIPADDRESS:", tf.indent(8))
			ln += label + strings.Join(ss, "\n"+label)
		}
	case "2.5.29.19":
		r = "X509v3 Basic Constraints:"
		isCAText := "FALSE"
		if cert.IsCA {
			isCAText = "TRUE"
		}
		ln = fmt.Sprintf("%sCA:%s", tf.indent(8), isCAText)
	case "2.5.29.15":
		var ss []string
		r = fmt.Sprintf("X509v3 Key Usage:%s", isCriticalText)

		for i, u := range []string{
			"Digital Signature",
			"Content Commitment",
			"Key Encipherment",
			"Data Encipherment",
			"Key Agreement",
			"Key Cert Signature",
			"CRL Signnature",
			"Encipher Only",
			"Decipher Only",
		} {
			if cert.KeyUsage&(1<<uint(i)) != 0 {
				ss = append(ss, u)
			}
		}

		if len(ss) > 0 {
			ln = fmt.Sprintf("%s%s", tf.indent(8), strings.Join(ss, ", "))
		}
	case "2.5.29.14":
		r = "X509v3 Subject Key Identifier:"
		ln = fmt.Sprintf("%s%s", tf.indent(8), strings.Replace(fmt.Sprintf("% X", cert.SubjectKeyId), " ", ":", -1))
	case "2.5.29.35":
		r = "X509v3 Authority Key Identifier:"
		ln = fmt.Sprintf("%skeyid:%s", tf.indent(8), strings.Replace(fmt.Sprintf("% X", cert.AuthorityKeyId), " ", ":", -1)) + "\n"
	case "2.5.29.31":
		r = "X509v3 CRL Distribution Points:"
		label := fmt.Sprintf("%sURI:", tf.indent(8))
		ln = label + strings.Join(cert.CRLDistributionPoints, "\n"+label) + "\n"
	case "2.5.29.37":
		var ss []string
		r = "X509v3 Extended Key Usage:"
		for _, v := range cert.ExtKeyUsage {
			ss = append(ss, extKeyUsage[v])
		}
		if len(ss) > 0 {
			ln = fmt.Sprintf("%s%s", tf.indent(8), strings.Join(ss, ", "))
		}
	case "2.5.29.32":
		r = "X509v3 Certificate Policies:"
		ln = tf.Policy(cIdx, pe)
	case "1.3.6.1.5.5.7.1.1":
		var ss []string
		r = "Authority Information Access:"
		if len(cert.OCSPServer) > 0 {
			ss = append(ss, fmt.Sprintf("%sOCSP - URI:%s", tf.indent(8), strings.Join(cert.OCSPServer, ", ")))
		}
		if len(cert.IssuingCertificateURL) > 0 {
			ss = append(ss, fmt.Sprintf("%sCA Issuers - URI:%s", tf.indent(8), strings.Join(cert.IssuingCertificateURL, ", ")))
		}
		ln = strings.Join(ss, "\n") + "\n"

	default:
		r = pe.Id.String() + ":"
		ln = tf.RawExtension(pe)
	}

	return fmt.Sprintf("\n%s%s\n%s", tf.indent(6), r, ln)
}
