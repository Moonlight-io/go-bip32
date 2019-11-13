package bip32

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/FactomProject/basen"
	"golang.org/x/crypto/ripemd160"
	"io"
	"math/big"
	"github.com/Moonlight-io/asteroid-core/models/primatives"
)

var (
	BitcoinBase58Encoding = basen.NewEncoding("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
)

//
// Hashes
//

func hashSha256(data []byte) []byte {
	hasher := sha256.New()
	hasher.Write(data)
	return hasher.Sum(nil)
}

func hashDoubleSha256(data []byte) []byte {
	return hashSha256(hashSha256(data))
}

func hashRipeMD160(data []byte) []byte {
	hasher := ripemd160.New()
	io.WriteString(hasher, string(data))
	return hasher.Sum(nil)
}

func hash160(data []byte) []byte {
	return hashRipeMD160(hashSha256(data))
}

//
// Encoding
//

func checksum(data []byte) []byte {
	return hashDoubleSha256(data)[:4]
}

func addChecksumToBytes(data []byte) []byte {
	checksum := checksum(data)
	return append(data, checksum...)
}

func base58Encode(data []byte) []byte {
	return []byte(BitcoinBase58Encoding.EncodeToString(data))
}

// Keys
func publicKeyForPrivateKey(curve primatives.EllipticCurve, key []byte) []byte {
	var keyBigInt big.Int
	keyBigInt.SetBytes(key)
	return compressPublicKey(curve.ScalarBaseMult(&keyBigInt))
}

func addPublicKeys(curve primatives.EllipticCurve, key1 []byte, key2 []byte) []byte {
	p1 := expandPublicKey(curve, key1)
	p2 := expandPublicKey(curve, key2)
	return compressPublicKey(curve.Add(p1, p2))
}

func addPrivateKeys(curve primatives.EllipticCurve, key1 []byte, key2 []byte) []byte {
	var key1Int big.Int
	var key2Int big.Int
	key1Int.SetBytes(key1)
	key2Int.SetBytes(key2)

	key1Int.Add(&key1Int, &key2Int)
	key1Int.Mod(&key1Int, curve.N)

	b := key1Int.Bytes()
	if len(b) < 32 {
		extra := make([]byte, 32-len(b))
		b = append(extra, b...)
	}
	return b
}

func compressPublicKey(p primatives.Point) []byte {
	var key bytes.Buffer

	// Write header; 0x2 for even y value; 0x3 for odd
	key.WriteByte(byte(0x2) + byte(p.Y.Bit(0)))

	// Write X coord; Pad the key so x is aligned with the LSB. Pad size is key length - header size (1) - xBytes size
	xBytes := p.X.Bytes()
	for i := 0; i < (PublicKeyCompressedLength - 1 - len(xBytes)); i++ {
		key.WriteByte(0x0)
	}
	key.Write(xBytes)

	return key.Bytes()
}

// As described at https://bitcointa.lk/threads/compressed-keys-y-from-x.95735/
func expandPublicKey(curve primatives.EllipticCurve, key []byte) (primatives.Point) {
	var point primatives.Point
	qPlus1Div4 := big.NewInt(0)
	point.X.SetBytes(key[1:])

	// y^2 = x^3 + ax^2 + b
	// a = 0
	// => y^2 = x^3 + b
	ySquared := point.X.Exp(point.X, big.NewInt(3), nil)
	ySquared.Add(ySquared, curve.B)

	qPlus1Div4.Add(curve.P, big.NewInt(1))
	qPlus1Div4.Div(qPlus1Div4, big.NewInt(4))

	// sqrt(n) = n^((q+1)/4) if q = 3 mod 4
	point.Y.Exp(ySquared, qPlus1Div4, curve.P)

	if uint32(key[0])%2 == 0 {
		point.Y.Sub(curve.P, point.Y)
	}

	return point
}

func validatePrivateKey(curve primatives.EllipticCurve, key []byte) error {
	if fmt.Sprintf("%x", key) == "0000000000000000000000000000000000000000000000000000000000000000" || //if the key is zero
		bytes.Compare(key, curve.N.Bytes()) >= 0 || //or is outside of the curve
		len(key) != 32 { //or is too short
		return errors.New("Invalid seed")
	}

	return nil
}

func validateChildPublicKey(curve primatives.EllipticCurve, key []byte) error {
	point := expandPublicKey(curve, key)

	if point.X.Sign() == 0 || point.Y.Sign() == 0 {
		return errors.New("Invalid public key")
	}

	return nil
}

//
// Numerical
//
func uint32Bytes(i uint32) []byte {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, i)
	return bytes
}
