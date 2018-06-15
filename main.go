package main

import (
	"fmt"
	"encoding/hex"
	"log"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"github.com/btcsuite/btcd/btcec"
	"crypto/sha256"
	"golang.org/x/crypto/ripemd160"
)

const version = byte(0x00)

func main() {
	fmt.Println("Golang generate a bitcoin address from a private key!")
	privKey := "ef6b6acd4bf8677e8a56ae3ee12e0984e5287b8fbf9769e9bee869e53de11092"
	test(privKey)

	// test private key to public key here: http://gobittest.appspot.com/Address uncompressed address
	// https://bitcore.io/playground/#/address compressed address

}

func test(privKey string){
	privByte,err := hex.DecodeString(privKey)

	if err!=nil{
		log.Panic(err)
	}

	priv, pubKey := PrivKeyFromBytes( btcec.S256(), privByte); //secp256k1
	pub := append(pubKey.X.Bytes(), pubKey.Y.Bytes()...)

	fmt.Printf("Priv key: %X\n", priv)
	fmt.Printf("Publick key: %X\n", pub)

	fmt.Printf("UnCommpressed Public Address: %s\n", getUncompressedPubKey(pubKey))
	fmt.Printf("Commpressed Public Address: %s\n", getCompressedPubKey(pubKey))
}


/*
https://bitcoin.stackexchange.com/questions/69315/how-are-compressed-pubkeys-generated
Look at the value of the y-coordinate.  If the last digit is an odd number (1, 3, 5, 7, 9) then use a prefix of "03". If it is not an odd number (0, 2, 4, 6, 8 ) then use a prefix of "02"
https://bitcointalk.org/index.php?topic=2185929.msg21939806#msg21939806
https://bitcoin.stackexchange.com/questions/3059/what-is-a-compressed-bitcoin-key
*/

func getUncompressedPubKey(publicKey *ecdsa.PublicKey) string{
	pub := append(publicKey.X.Bytes(), publicKey.Y.Bytes()...)
	uncompressedPub := append([]byte{0x04}, pub...)
	key := fmt.Sprintf("%s", getAddress(uncompressedPub))
	return key
}

func getCompressedPubKey(publicKey *ecdsa.PublicKey) string{
	var compressedPub []byte

	if isOdd(publicKey.Y){
		compressedPub =  append([]byte{0x03}, publicKey.X.Bytes()...)
	}else{
		compressedPub =  append([]byte{0x02}, publicKey.X.Bytes()...)
	}
	key := fmt.Sprintf("%s", getAddress(compressedPub))
	return key
}


func isOdd(b *big.Int) bool{
	if b.Bit(0) == 0 {
		return false
	} else {
		return true
	}
}

func PrivKeyFromBytes(curve elliptic.Curve, pk []byte) (*ecdsa.PrivateKey,
	*ecdsa.PublicKey) {
	x, y := curve.ScalarBaseMult(pk)

	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: new(big.Int).SetBytes(pk),
	}

	return (*ecdsa.PrivateKey)(priv), (*ecdsa.PublicKey)(&priv.PublicKey)
}

func checksum(payload []byte) []byte{
	firstSHA := sha256.Sum256(payload)
	secondSHA := sha256.Sum256(firstSHA[:])
	return secondSHA[:4]
}

func HashPubKey(pubKey []byte) []byte{
	publicSHA256 := sha256.Sum256(pubKey)
	RIPEMD160Hasher := ripemd160.New()
	_, err := RIPEMD160Hasher.Write(publicSHA256[:])
	if err != nil{
		log.Panic(err)
	}
	publicRIPEMD160 := RIPEMD160Hasher.Sum(nil)
	return publicRIPEMD160

}

func getAddress(pubKey []byte) []byte{
	pubKeyHash := HashPubKey(pubKey)
	versionedPayload := append([]byte{version}, pubKeyHash...)
	checksum :=  checksum(versionedPayload)
	fullpayload := append(versionedPayload, checksum...)
	address := Base58Encode(fullpayload)
	return address
}