package goproxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/hashicorp/go-rootcerts"
)

var GoproxyCaConfig *GoproxyConfig

func rootCAs(c *rootcerts.Config) *tls.Config {
	t := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS12,
		Renegotiation:      tls.RenegotiateFreelyAsClient,
	}
	err := rootcerts.ConfigureTLS(t, c)
	if err != nil {
		fmt.Println("[Warning] Error loading root certs", err)
	}
	return t
}

func init() {
	config, err := LoadCAConfig(CA_CERT, CA_KEY)
	if err != nil {
		panic("Error parsing builtin CA " + err.Error())
	}
	GoproxyCaConfig = config
}

// Load a CAConfig bundle from by arrays.  You can then load them into
// the proxy with `proxy.SetMITMCertConfig`
func LoadCAConfig(caCert, caKey []byte) (*GoproxyConfig, error) {
	ca, err := tls.X509KeyPair(caCert, caKey)
	if err != nil {
		return nil, err
	}
	priv := ca.PrivateKey

	ca509, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return nil, err
	}
	config, err := NewConfig(ca509, priv)
	return config, err
}

var tlsClientSkipVerify = rootCAs(nil)

var CA_CERT = []byte(`-----BEGIN CERTIFICATE-----
MIIC/TCCAeWgAwIBAgIRALVzNa8DPRRGV0QBro07S7UwDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAeFw0xNzAyMTYxNTA0MDVaFw0yNzAyMTQxNTA0
MDVaMBIxEDAOBgNVBAoTB0FjbWUgQ28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQCf5PWDdpWwMSSogQ0EcvR58pkU5tncQ9ektJ0GSrfLd/hR17M5+xKq
cFDlWGB7uKUU+6uM4UQnrbYzx97MUCnh5Ie58Hgb9jdx+A3eYCzneJWoBtJcsiMd
TFbjVEuqyFWVcy/dzfrmwEiyH2xHmMhJ/SnVpZa1MG9bjxJwuUECQMjbShePW5bK
XCMpIGyqHENRQg6wXRf1NykaSD+2yu4v+sljiCDy/VbmJDkoiyRtBsdxTncITKa3
LPbZnZtJS26SpYkDpNpAzt2bWkkrxh9isV2S4MNqrO7CjNNawEmkSs7yv+LhCvYN
i+9x3QTuJJ3QEoxIjJ2qv02tzlj5RidXAgMBAAGjTjBMMA4GA1UdDwEB/wQEAwIC
pDATBgNVHSUEDDAKBggrBgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MBQGA1UdEQQN
MAuCCWxvY2FsaG9zdDANBgkqhkiG9w0BAQsFAAOCAQEAZq4a3eBSmC3PCD8Pte4h
zdgTNK22Zh1YCD+rVaDC8v9igJ69s+ggQl1VwzgIUd90mXAElBHmqjPffT5Ao1E5
ph+7Kdt4H04ugpLDZGfeOB6k5OMRbiEvgz5XRVPQVBcLTAvEit23ifVSbqkfMRh5
dO3dhRG0sxdKN+eFzxnXp4mGpcIniPYTsRE0Zee5ESMsw72S6iFFR9pokhUw9ESN
EQ+bJpd63nxMEkahFHBBrC/74obmg58pYbGyVlE1UuqN49WYgqL83Id+EQSwHzrn
hNqXKv3sGnFl4uUCRCc/PNRUdCkhPp5v9W6k5rMYwGxBb4QBrU12PpUWoqwV8dFi
8A==
-----END CERTIFICATE-----`)

var CA_KEY = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAn+T1g3aVsDEkqIENBHL0efKZFObZ3EPXpLSdBkq3y3f4Udez
OfsSqnBQ5Vhge7ilFPurjOFEJ622M8fezFAp4eSHufB4G/Y3cfgN3mAs53iVqAbS
XLIjHUxW41RLqshVlXMv3c365sBIsh9sR5jISf0p1aWWtTBvW48ScLlBAkDI20oX
j1uWylwjKSBsqhxDUUIOsF0X9TcpGkg/tsruL/rJY4gg8v1W5iQ5KIskbQbHcU53
CEymtyz22Z2bSUtukqWJA6TaQM7dm1pJK8YfYrFdkuDDaqzuwozTWsBJpErO8r/i
4Qr2DYvvcd0E7iSd0BKMSIydqr9Nrc5Y+UYnVwIDAQABAoIBAHkVzI832HfLX3Vz
9UWvQFCxVRgtEkLp5X5HgLppDvK48YYZERMRfbswvzJPURGgbPOM+wb++LwLovVn
oOOcuXrls5st7edO+AII1YfX0WmhOcQ7Fkc4Z7siOpKBHaRBff5lcpRIDn98khDC
Fx/JJbRSUcIHWi/wdAQkPtS6le57qqBl2wGRIbV3/6Hjq15X2UJCtzrGjY3IcYKp
lwL2C7boEEppQLXodVdXewfoM+6v76g/Vtx4qaLapCaVnv8GthtcejQhHIgZO5ZR
j1ANuaVWPDi0CoLWDCQAOlrDiQbTQtdgyV0uG+3JGxW2SW2uv15N9Fn1eELf8S29
CwmW6yECgYEAzqDwjRR+sOMdUKHCPHYHa+7V1t/dvmaEJaSsORo9gMLauqLbQGy5
2zTIHoIzIzrW6IjFtVkThKmof+6JdBbINKShLtkNsl3Pr9fuhRsE7qxTnWen4BmM
p4fx83xhQrEcSya+9Uj19spfKTxM/+sfhGhKavWjJ+0Fumqd8IMuvskCgYEAxhlg
UmSZeWSXJ9CGUpu+eZkZdoUQxGwzka9iuGE/qM1eFWd7idx4owexaHLOqf9rxACb
fuMbREOn+n8zsTynsvNLw6CPtDlV4QB08wcFX14hk+WGDujDWppOyiXKsytHzUmG
Q1KycHwa/qVNVtSy2hlRtJxYNwwDupRl73+6JR8CgYAqLprNAkkWzVaXtl4Tv7im
JRzMf+khzIXftW1fPucdWSoT/dkqnseWY4ETEVtlLsbes8VAz013wLbgXw76fwgi
DxXEnZT5O8OBT2CnFav9GXr8YEPaMP0Q2mTfYx3r4oI3KVLEej+UQR4KKgBCInrN
qgi/KyRCq1WHB+r0RaOOWQKBgETibBkafDe3H8yreRneqGRWNYF+Ee+LhH8jUpu0
zVMgXpfozQ+KR7TBJxKf4XdBpzKX13pO9JtPP2ketFXsNpBGg9D50x6jVVaRNxmP
FnIsJFbuWCh1DgFCaSVn8M1OvoAHEhX0+rGcpjJoPrVz7uFiLoQ0XYR+vAk0MyIN
8yeXAoGAEYDoNb8fcOnUOac9ziIqP2cZkl3jY9bom2Pm4xgsxrvdT29WTdKUXDnv
McrO0jsnBcEeA2jQjCZ5ZZ6zsKRvPtYHjHzcUCYhc1HI5QIK49ObuHGGzYIPhcIv
irIev81IwGZcLkKJ1U1P7sDpT07gXpdKMAfur6OgSd3oq25NH8E=
-----END RSA PRIVATE KEY-----`)
