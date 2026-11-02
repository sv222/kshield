package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

const (
	privateKeyType = "PRIVATE KEY"
	publicKeyType  = "PUBLIC KEY"
	privateKeyMode = 0o600
	publicKeyMode  = 0o644
)

func GenerateKey(prefix string) error {
	keyPath, pubPath := prefix+".key", prefix+".pub"
	for _, p := range []string{keyPath, pubPath} {
		if _, err := os.Lstat(p); err == nil {
			return fmt.Errorf("evidence: %s already exists", p)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("evidence: %w", err)
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("evidence: generate key: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("evidence: encode private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("evidence: encode public key: %w", err)
	}
	if err := writeNew(keyPath, pem.EncodeToMemory(&pem.Block{Type: privateKeyType, Bytes: privDER}), privateKeyMode); err != nil {
		return fmt.Errorf("evidence: write private key: %w", err)
	}
	if err := writeNew(pubPath, pem.EncodeToMemory(&pem.Block{Type: publicKeyType, Bytes: pubDER}), publicKeyMode); err != nil {
		_ = os.Remove(keyPath)
		return fmt.Errorf("evidence: write public key: %w", err)
	}
	return nil
}

func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	der, err := readPEM(path, privateKeyType)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("evidence: %s: not a PKCS#8 private key", path)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("evidence: %s: not an ed25519 private key", path)
	}
	return priv, nil
}

func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	der, err := readPEM(path, publicKeyType)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("evidence: %s: not a PKIX public key", path)
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("evidence: %s: not an ed25519 public key", path)
	}
	return pub, nil
}

func readPEM(path, blockType string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("evidence: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != blockType {
		return nil, fmt.Errorf("evidence: %s: not a PEM %s", path, blockType)
	}
	return block.Bytes, nil
}
