[![Build Status](https://travis-ci.org/njones/pbr.svg?branch=master)](https://travis-ci.org/njones/pbr) [![Go Report Card](https://goreportcard.com/badge/github.com/njones/pbr)](https://goreportcard.com/report/github.com/njones/pbr)

# PBR - PEM Block Reader #

PBR is a binary written in Go that takes a multi-block .pem file and outputs each block formatted in the same style as OpenSSL. Currently OpenSSL can only read the first block in a multi-block .pem file.

Also to read different types of PEM encoded blocks, OpenSSL needs to use different command line options (for which you need to remember --or lookup each time). PBR jhas no arguments and will auto-detect the block type to print to stdout, or it can with an optional "-out" argument output the results to a file.

#### Note ####
> This currently reads only RSA blocks

## Binary ##

This is a command line application and not a library, therefore download the latest release to use it immediately.

## Usage ##

    pbr -in server.pem

Produces the following sample output:

    Certificate:
        Data:
            Version: 3 (0x2)
            Serial Number:
                31:9c:30:9f:99:50:97:c8:29:19:b1:80
            Signature Algorithm: sha256WithRSAEncryption
            Issuer: C=BE, O=GlobalSign nv-sa, CN=AlphaSSL CA - SHA256 - G2
            Validity
                Not Before: Mar  6 03:40:47 2000 GMT
                Not After : Jun 20 15:18:17 2010 GMT
            Subject: OU=Domain Control Validated, CN=*.example.com
            Subject Public Key Info:
                Public Key Algorithm: rsaEncryption
                RSA Public Key: (2048 bit)
                    Modulus (2048 bit):
                        00:dc:e6:ac:f3:db:56:ed:33:27:51:19:d6:30:fa:
                        35:56:a0:f9:19:eb:d1:27:35:e3:51:6f:24:7d:f2:
                        42:cd:6a:30:ec:b1:30:e2:1f:57:ea:cc:33:0d:84:
                        9a:76:ac:e8:37:b2:b6:f2:45:03:92:73:89:1a:c2:
                        ff:06:50:06:19:58:0a:d8:45:70:8f:d8:bd:e2:98:
                        bf:30:9a:12:d2:b5:aa:33:1d:cf:72:27:9f:23:65:
                        dc:c1:7c:06:55:3e:0f:89:62:a1:9f:cd:0e:4f:f0:
                        8c:60:33:2d:8f:2c:c6:f0:43:6d:12:4a:4b:19:d8:
                        c0:ee:49:d5:aa:0a:f9:8e:fc:12:aa:ef:13:78:84:
                        2e:9c:15:28:72:c8:8f:57:d6:df:2c:48:3b:06:85:
                        34:a1:f3:d7:0f:20:38:48:b5:64:25:fb:24:c5:94:
                        c3:cb:1f:3b:31:0d:4a:85:71:bb:ef:0b:af:e6:66:
                        f1:e9:af:9c:1b:c2:d6:7d:87:78:76:a5:98:74:a9:
                        4d:40:75:81:a0:2e:00:25:ba:71:94:b9:2d:fa:51:
                        bc:45:43:d5:dc:d2:97:a6:3f:da:e3:8a:11:f2:05:
                        66:0a:29:0d:2d:6f:f4:39:5c:5a:e1:8d:d9:01:48:
                        89:9c:b1:8e:e8:9f:54:38:59:84:23:df:e3:e8:55:
                        4c:a7
                    Exponent: 65537 (0x10001)
            X509v3 extensions:
                X509v3 Key Usage: critical
                    Digital Signature, Key Encipherment
                Authority Information Access:
                    OCSP - URI:http://ocsp2.globalsign.com/gsalphasha2g2
                    CA Issuers - URI:http://secure2.alphassl.com/cacert/gsalphasha2g2r1.crt

                X509v3 Certificate Policies:
                    Policy: 
                    CPS: https://www.globalsign.com/repository/

                X509v3 Basic Constraints:
                    CA:FALSE
                X509v3 CRL Distribution Points:
                    URI:http://crl2.alphassl.com/gs/gsalphasha2g2.crl

                X509v3 Subject Alternative Name:
                    DNS:*.cnf.mobimic.com
                    DNS:cnf.mobimic.com
                X509v3 Extended Key Usage:
                    TLS Web Server Authentication, TLS Web Client Authentication
                X509v3 Subject Key Identifier:
                    50:00:4B:8C:44:E8:56:6C:65:99:6D:68:81:80:3F:D1:64:9D:BD:7E
                X509v3 Authority Key Identifier:
                    keyid:F5:CD:D5:3C:08:50:F9:6A:4F:3A:B7:97:DA:56:83:E6:69:D2:68:F7

                1.3.6.1.4.1.11129.2.4.2:
    O. ....hp~.....\..=..........Z.........H0F.!.....}.NF.........d.k.../.....'...!...=..KOqL.....:........W....7..X.v.V.../.......D.
    >.Fv....\....U.......Z...7.....G0E. ... ..Q.._.hc.....'..[D.......Cv.!.......$..e@..=Q..I&.....4.....Q..v.......X......gp.<5.....
    ..w.........Z.........G0E. \.[..F..C...J0'...f.....+...W*...!..;....b.<.F.b..d{..Ph^..P0.l..\..w.......q...#...{G8W...R....d6....
    ...Z...N.....H0F.!.. ...#......-f......+l..K...`....!...O..[...<...n....9..m#....90....v..K..u.`..Bi....f..~_.r....{.z......Z....
    .....G0E. s.N6.....l...l...-..Q..........p.!..n..8..P......../..R..o.....zK%.
        Signature Algorithm: sha256WithRSAEncryption
            8c:d6:30:20:80:a3:d8:b7:61:fe:55:43:fc:68:5d:cf:21:b8:
            29:72:a9:1b:99:52:80:8d:3a:59:5d:72:be:00:25:4e:d7:74:
            18:61:15:be:d0:bc:13:97:fb:c9:0a:fc:d2:cb:15:9a:9c:01:
            08:72:b4:bb:41:bc:ab:d8:13:dd:8e:4f:d8:49:91:48:7e:de:
            b3:10:d8:34:5d:79:33:84:49:b7:cc:e8:93:62:d1:20:63:32:
            1a:98:b6:2d:91:ea:b8:49:ca:e4:ae:56:b8:44:ba:1f:31:70:
            c4:e1:d9:67:7a:b3:7f:1a:c3:4c:57:90:34:4f:20:ad:f3:38:
            35:3c:99:e3:b1:df:09:7b:08:9a:d2:0b:86:9e:17:af:d7:40:
            7a:c1:bc:dd:7d:26:17:25:0f:44:22:00:13:f5:04:c1:9a:60:
            4b:f8:fa:4f:b1:c8:a3:77:ec:42:ae:2d:00:49:ce:8e:fd:e7:
            64:a3:07:a1:f1:3c:e4:7e:84:0f:ed:b5:2a:0c:d3:a3:1a:cd:
            2e:71:93:70:af:ef:bd:00:3e:e3:57:ae:b1:ca:91:f2:1b:e4:
            ae:e0:5f:59:2d:6d:b1:33:df:55:76:ea:d3:52:8e:1a:5e:92:
            4e:96:b8:91:0b:f6:6d:3e:1f:ba:68:f2:d3:66:f0:f5:ab:44:
            ca:9a:92:b8
    -----------------------------------------------------------------
    Certificate:
        Data:
            Version: 3 (0x2)
            Serial Number:
                04:00:00:00:00:01:44:4e:f0:36:31
            Signature Algorithm: sha256WithRSAEncryption
            Issuer: C=BE, O=GlobalSign nv-sa, OU=Root CA, CN=GlobalSign Root CA
            Validity
                Not Before: Feb 20 10:00:00 2014 GMT
                Not After : Feb 20 10:00:00 2024 GMT
            Subject: C=BE, O=GlobalSign nv-sa, CN=AlphaSSL CA - SHA256 - G2
            Subject Public Key Info:
                Public Key Algorithm: rsaEncryption
                RSA Public Key: (2048 bit)
                    Modulus (2048 bit):
                        00:da:01:ec:e4:ec:73:60:fb:7e:8f:6a:b7:c6:17:
                        e3:92:64:32:d4:ac:00:d9:a2:0f:b9:ed:ee:6b:8a:
                        86:ca:92:67:d9:74:d7:5d:47:02:3c:8f:40:d6:9e:
                        6d:14:cd:c3:da:29:39:a7:0f:05:0a:68:a2:66:1a:
                        1e:c4:b2:8b:76:58:e5:ab:5d:1d:8f:40:b3:39:8b:
                        ef:1e:83:7d:22:d0:e3:a9:00:2e:ec:53:cf:62:19:
                        85:44:28:4c:c0:27:cb:7b:0e:ec:10:64:00:10:a4:
                        05:cc:a0:72:be:41:6c:31:5b:48:e4:b1:ec:b9:23:
                        eb:55:4d:d0:7d:62:4a:a5:b4:a5:a4:59:85:c5:25:
                        91:a6:fe:a6:09:9f:06:10:6d:8f:81:0c:64:40:5e:
                        73:00:9a:e0:2e:65:98:54:10:00:70:98:c8:e1:ed:
                        34:5f:d8:9c:c7:0d:c0:d6:23:59:45:fc:fe:55:7a:
                        86:ee:94:60:22:f1:ae:d1:e6:55:46:f6:99:c5:1b:
                        08:74:5f:ac:b0:64:84:8f:89:38:1c:a1:a7:90:21:
                        4f:02:6e:bd:e0:61:67:d4:f8:42:87:0f:0a:f7:c9:
                        04:6d:2a:a9:2f:ef:42:a5:df:dd:a3:53:db:98:1e:
                        81:f9:9a:72:7b:5a:de:4f:3e:7f:a2:58:a0:e2:17:
                        ad:67
                    Exponent: 65537 (0x10001)
            X509v3 extensions:
                X509v3 Key Usage: critical
                    Key Cert Signature, CRL Signnature
                X509v3 Basic Constraints:
                    CA:TRUE
                X509v3 Subject Key Identifier:
                    F5:CD:D5:3C:08:50:F9:6A:4F:3A:B7:97:DA:56:83:E6:69:D2:68:F7
                X509v3 Certificate Policies:
                    Policy: 
                    CPS: https://www.alphassl.com/repository/

                X509v3 CRL Distribution Points:
                    URI:http://crl.globalsign.net/root.crl

                Authority Information Access:
                    OCSP - URI:http://ocsp.globalsign.com/rootr1

                X509v3 Authority Key Identifier:
                    keyid:60:7B:66:1A:45:0D:97:CA:89:50:2F:7D:04:CD:34:A8:FF:FC:FD:4B

        Signature Algorithm: sha256WithRSAEncryption
            60:40:68:16:47:e7:16:8d:db:5c:a1:56:2a:cb:f4:5c:9b:b0:
            1e:a2:4b:f5:cb:02:3f:f8:0b:a1:f2:a7:42:d4:b7:4c:eb:e3:
            66:80:f3:25:43:78:2e:1b:17:56:07:52:18:cb:d1:a8:ec:e6:
            fb:73:3e:a4:62:8c:80:b4:d2:c5:12:73:a3:d3:fa:02:38:be:
            63:3d:84:b8:99:c1:f1:ba:f7:9f:c3:40:d1:58:18:53:c1:62:
            dd:af:18:42:7f:34:4e:c5:43:d5:71:b0:30:00:c7:e3:90:ae:
            3f:57:86:97:ce:ea:0c:12:8e:22:70:e3:66:a7:54:7f:2e:28:
            cb:d4:54:d0:b3:1e:62:67:08:f9:27:e1:cb:e3:66:b8:24:1b:
            89:6a:89:44:65:f2:d9:4c:d2:58:1c:8c:4e:c0:95:a1:d4:ef:
            67:2f:38:20:e8:2e:ff:96:51:f0:ba:d8:3d:92:70:47:65:1c:
            9e:73:72:b4:60:0c:5c:e2:d1:73:76:e0:af:4e:e2:e5:37:a5:
            45:2f:8a:23:3e:87:c7:30:e6:31:38:7c:f4:dd:52:ca:f3:53:
            04:25:57:56:66:94:e8:0b:ee:e6:03:14:4e:ee:fd:6d:94:64:
            9e:5e:ce:79:d4:b2:a6:cf:40:b1:44:a8:3e:87:19:5e:e9:f8:
            21:16:59:53
    done.

