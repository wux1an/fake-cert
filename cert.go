package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randStringN(min, max int) string {
	return randString(min + randInt(max-min))
}

func randString(n int) string {
	r := make([]byte, n)
	_, err := rand.Read(r)
	if err != nil {
		return ""
	}

	b := make([]byte, n)
	l := len(letters)
	for i := range b {
		b[i] = letters[int(r[i])%l]
	}
	return string(b)
}

func randBytes(n int) []byte {
	r := make([]byte, n)
	_, _ = rand.Read(r)
	return r
}

func randBigInt(max *big.Int) *big.Int {
	r, _ := rand.Int(rand.Reader, max)
	return r
}

func randInt(max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(n.Int64())
}

func randomDate() time.Time {
	days := randInt(356 * 3)
	hour := 6 + randInt(24-6)
	tmp := time.Now().AddDate(0, 0, -days)
	return time.Date(tmp.Year(), tmp.Month(), tmp.YearDay(), hour, 0, 0, 0, time.UTC)
}

func genPair(keySize int) (caCert []byte, caKey []byte, cert []byte, certKey []byte) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	validity := 1 + randInt(9)
	ca := &x509.Certificate{
		SerialNumber: randBigInt(serialNumberLimit),
		Subject: pkix.Name{
			CommonName:         randStringN(4, 16),
			Country:            []string{randStringN(4, 16)},
			Organization:       []string{randStringN(4, 16)},
			OrganizationalUnit: []string{randStringN(4, 16)},
		},
		SubjectKeyId:          randBytes(5),
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	ca.NotBefore = randomDate()
	ca.NotAfter = ca.NotBefore.AddDate(validity, 0, 0)

	priv, _ := rsa.GenerateKey(rand.Reader, keySize)
	pub := &priv.PublicKey
	caBin, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
	if err != nil {
		return
	}

	cert2 := &x509.Certificate{
		SerialNumber: randBigInt(serialNumberLimit),
		Subject: pkix.Name{
			CommonName:         randStringN(4, 16),
			Country:            []string{randStringN(4, 16)},
			Organization:       []string{randStringN(4, 16)},
			OrganizationalUnit: []string{randStringN(4, 16)},
		},
		SubjectKeyId: randBytes(6),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	cert2.NotBefore = ca.NotBefore
	cert2.NotAfter = ca.NotAfter

	priv2, _ := rsa.GenerateKey(rand.Reader, keySize)
	pub2 := &priv2.PublicKey
	cert2Bin, err2 := x509.CreateCertificate(rand.Reader, cert2, ca, pub2, priv)
	if err2 != nil {
		return
	}

	privBin := x509.MarshalPKCS1PrivateKey(priv)
	priv2Bin := x509.MarshalPKCS1PrivateKey(priv2)

	return caBin, privBin, cert2Bin, priv2Bin

}

func getPEMs(cert []byte, key []byte) (pemcert []byte, pemkey []byte) {
	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})

	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: key,
	})

	return certPem, keyPem
}

func Random(keySize int) tls.Certificate {
	_, _, cert, certKey := genPair(keySize)
	certPem, keyPem := getPEMs(cert, certKey)
	tlsPair, _ := tls.X509KeyPair(certPem, keyPem)
	return tlsPair
}
