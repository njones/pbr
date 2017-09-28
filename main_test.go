package main

import (
	"bytes"
	"os"
	"testing"
)

func TestMain(t *testing.T) {
	val, err := os.Open("test/localhost.rsa.key")
	if err != nil {
		t.Errorf("open .pem failed: %v", err)
	}
	buf := new(bytes.Buffer)
	parse(val, buf)
	if buf.String() != expectKey {
		t.Errorf("have:\n%s\nwant:\n%s", buf.String(), expectKey)
	}

	val, err = os.Open("test/localhost.rsa.crt")
	if err != nil {
		t.Errorf("open .pem failed: %v", err)
	}
	buf.Reset()
	parse(val, buf)
	if buf.String() != expectCrt {
		t.Errorf("have:\n%s\nwant:\n%s", buf.String(), expectCrt)
	}

	val, err = os.Open("test/localhost.rsa.csr")
	if err != nil {
		t.Errorf("open .pem failed: %v", err)
	}
	buf.Reset()
	parse(val, buf)
	if buf.String() != expectCrtReq {
		t.Errorf("have:\n%s\nwant:\n%s", buf.String(), expectCrtReq)
	}
}

var expectKey = `Private Key:
Modulus (2048 bit):
          00:bf:c1:5f:ee:d7:93:5e:70:72:c5:10:f7:e1:3e:
          61:c0:e9:8d:3d:d9:30:f4:2b:27:0a:55:ab:a0:02:
          7a:ec:c7:e9:5f:f4:3b:ef:03:59:05:15:ad:84:31:
          28:b8:2b:e9:d5:1b:94:de:13:ac:71:2d:25:2e:68:
          dc:f3:b3:7e:6b:37:3a:da:a5:9e:d8:fc:ea:bc:d5:
          28:fe:cc:4f:d6:2b:90:97:7a:e2:13:f1:58:bf:00:
          e5:9a:9c:7a:c6:bc:3b:30:ff:64:f8:4e:b6:9f:5a:
          38:81:f6:59:91:1e:d5:cb:6d:1f:27:d2:13:9e:e3:
          de:a9:d9:61:4d:ff:bd:5c:db:14:97:13:1b:d4:bf:
          e5:8f:52:ae:8c:eb:c9:7c:34:d5:f0:e5:1b:ed:77:
          ce:44:c1:05:c9:01:97:99:7a:c7:97:47:a4:d5:46:
          bc:da:43:f0:9c:c1:bf:8d:dd:90:b3:8c:50:ae:2d:
          c5:d0:37:66:a4:47:ec:dc:12:79:33:cf:29:1e:8f:
          72:3b:df:03:82:c7:47:67:1b:e1:40:1c:f4:13:4d:
          b1:bf:49:d9:7a:ab:52:fe:9a:2f:52:65:cf:fc:29:
          08:e0:53:5e:14:bb:02:fe:8b:4f:b6:3f:65:85:56:
          f7:78:68:25:06:96:3f:0c:df:ec:bf:4f:30:3d:65:
          b9:8b
done.
`

var expectCrt = `Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            90:da:29:41:f7:70:c5:ce
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, ST=California, L=Mountain View, O=The Next 1x10e100, OU=Miles, CN=Testing 123
        Validity
            Not Before: Sep 26 17:45:20 2017 GMT
            Not After : Sep 26 17:45:20 2018 GMT
        Subject: C=US, ST=California, L=Mountain View, O=The Next 1x10e100, OU=Miles, CN=Testing 123
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:bf:c1:5f:ee:d7:93:5e:70:72:c5:10:f7:e1:3e:
                    61:c0:e9:8d:3d:d9:30:f4:2b:27:0a:55:ab:a0:02:
                    7a:ec:c7:e9:5f:f4:3b:ef:03:59:05:15:ad:84:31:
                    28:b8:2b:e9:d5:1b:94:de:13:ac:71:2d:25:2e:68:
                    dc:f3:b3:7e:6b:37:3a:da:a5:9e:d8:fc:ea:bc:d5:
                    28:fe:cc:4f:d6:2b:90:97:7a:e2:13:f1:58:bf:00:
                    e5:9a:9c:7a:c6:bc:3b:30:ff:64:f8:4e:b6:9f:5a:
                    38:81:f6:59:91:1e:d5:cb:6d:1f:27:d2:13:9e:e3:
                    de:a9:d9:61:4d:ff:bd:5c:db:14:97:13:1b:d4:bf:
                    e5:8f:52:ae:8c:eb:c9:7c:34:d5:f0:e5:1b:ed:77:
                    ce:44:c1:05:c9:01:97:99:7a:c7:97:47:a4:d5:46:
                    bc:da:43:f0:9c:c1:bf:8d:dd:90:b3:8c:50:ae:2d:
                    c5:d0:37:66:a4:47:ec:dc:12:79:33:cf:29:1e:8f:
                    72:3b:df:03:82:c7:47:67:1b:e1:40:1c:f4:13:4d:
                    b1:bf:49:d9:7a:ab:52:fe:9a:2f:52:65:cf:fc:29:
                    08:e0:53:5e:14:bb:02:fe:8b:4f:b6:3f:65:85:56:
                    f7:78:68:25:06:96:3f:0c:df:ec:bf:4f:30:3d:65:
                    b9:8b
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                3C:86:20:3A:0B:B7:4E:E2:89:84:05:1D:98:62:88:64:2B:E1:91:A0
            X509v3 Authority Key Identifier:
                keyid:3C:86:20:3A:0B:B7:4E:E2:89:84:05:1D:98:62:88:64:2B:E1:91:A0

            X509v3 Basic Constraints:
                CA:TRUE
    Signature Algorithm: sha256WithRSAEncryption
        99:40:0e:97:e6:87:fa:bb:c6:f6:40:e3:14:a5:b5:ed:97:60:
        72:91:a6:50:21:9c:f4:89:cf:56:4e:3a:0b:4e:d6:08:49:41:
        05:4a:47:41:69:d6:91:5c:c2:01:ff:9a:5f:3f:11:30:01:73:
        0b:17:41:3a:96:ed:0d:b2:dd:ee:53:b4:08:36:b1:f7:2d:ff:
        7b:6d:a7:82:1a:28:1a:55:aa:47:4e:88:e2:c2:aa:71:29:8f:
        3c:ba:8e:2b:95:db:74:26:48:7c:3c:61:24:8f:b7:1b:47:19:
        a0:6c:0f:91:02:55:88:9c:77:76:db:0f:ca:a6:97:90:45:4e:
        30:c5:98:df:f6:4d:02:6c:c5:27:db:d6:b1:ea:7c:1e:fa:8c:
        8d:02:21:b5:01:0c:da:46:67:aa:73:0c:59:7d:2e:6c:4c:ce:
        79:e8:78:7c:76:81:32:cf:e5:cf:c7:53:f7:bc:e9:61:d3:aa:
        4e:50:24:18:49:a3:9e:38:37:a1:c7:4b:9d:97:0d:09:dd:bd:
        34:b5:c7:b5:b0:06:fd:d4:f1:4c:23:f7:8e:ce:e2:b2:d3:a1:
        9c:31:ef:4c:c5:8d:2b:8e:19:4a:a1:04:01:02:ad:fc:97:21:
        d1:f9:fa:b3:b8:d9:29:32:2c:b7:3e:d2:4e:f8:3d:e9:56:2a:
        48:dd:85:55
done.
`

var expectCrtReq = `Certificate Request:
    Data:
        Version: 0 (0x0)
        Subject: C=US, ST=California, L=Mountain View, O=The next 1x10e100, OU=Dark Matter, CN=Testing ABC
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:bf:c1:5f:ee:d7:93:5e:70:72:c5:10:f7:e1:3e:
                    61:c0:e9:8d:3d:d9:30:f4:2b:27:0a:55:ab:a0:02:
                    7a:ec:c7:e9:5f:f4:3b:ef:03:59:05:15:ad:84:31:
                    28:b8:2b:e9:d5:1b:94:de:13:ac:71:2d:25:2e:68:
                    dc:f3:b3:7e:6b:37:3a:da:a5:9e:d8:fc:ea:bc:d5:
                    28:fe:cc:4f:d6:2b:90:97:7a:e2:13:f1:58:bf:00:
                    e5:9a:9c:7a:c6:bc:3b:30:ff:64:f8:4e:b6:9f:5a:
                    38:81:f6:59:91:1e:d5:cb:6d:1f:27:d2:13:9e:e3:
                    de:a9:d9:61:4d:ff:bd:5c:db:14:97:13:1b:d4:bf:
                    e5:8f:52:ae:8c:eb:c9:7c:34:d5:f0:e5:1b:ed:77:
                    ce:44:c1:05:c9:01:97:99:7a:c7:97:47:a4:d5:46:
                    bc:da:43:f0:9c:c1:bf:8d:dd:90:b3:8c:50:ae:2d:
                    c5:d0:37:66:a4:47:ec:dc:12:79:33:cf:29:1e:8f:
                    72:3b:df:03:82:c7:47:67:1b:e1:40:1c:f4:13:4d:
                    b1:bf:49:d9:7a:ab:52:fe:9a:2f:52:65:cf:fc:29:
                    08:e0:53:5e:14:bb:02:fe:8b:4f:b6:3f:65:85:56:
                    f7:78:68:25:06:96:3f:0c:df:ec:bf:4f:30:3d:65:
                    b9:8b
                Exponent: 65537 (0x10001)
        Attributes:
            a0:00
    Signature Algorithm: sha256WithRSAEncryption
        be:5a:71:9b:e6:0c:22:24:4c:1a:7a:7a:c4:13:00:3c:3d:dc:
        a9:54:d0:12:cf:5b:e1:6b:b9:a8:d9:25:bb:e9:ab:9d:90:f7:
        f4:96:21:49:aa:eb:6c:f9:84:18:c0:c7:7d:0c:c5:29:4d:b6:
        95:bc:09:1b:13:b2:80:2e:4b:a0:1c:1a:14:30:3a:02:9d:51:
        8c:51:7f:66:bf:4b:9e:bb:3b:f7:37:b7:93:a6:02:33:17:18:
        95:a3:c9:1a:22:50:35:18:dc:52:5e:f9:95:01:a8:78:ba:f2:
        17:4b:14:23:b1:90:d8:2a:68:78:7d:44:cf:c0:7d:0e:6f:1f:
        c5:d8:b6:65:43:f4:9a:78:05:ab:a7:2c:1a:8b:93:d0:55:0f:
        df:58:31:79:32:c8:dc:01:d5:0f:b2:10:c6:e5:e5:79:2e:d6:
        1a:5f:f7:78:87:fb:a3:7c:13:d2:d4:21:72:27:d5:c1:cd:35:
        61:fc:3b:22:14:1d:16:e1:a0:eb:46:94:d3:cb:2c:2c:96:dd:
        bb:11:4f:7a:3f:8b:2b:c4:66:6a:a6:57:60:ed:ce:53:96:d2:
        c2:e6:70:47:ba:cb:88:bb:e2:98:2c:f8:fb:cb:f2:b6:31:bf:
        6e:3c:ec:1e:88:1c:07:34:88:fd:f6:5b:df:54:dd:2c:2d:57:
        30:3d:27:2e
done.
`
