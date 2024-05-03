/*Can we send messages more than once?
Final implemententation
*/

package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "fmt"
    "math/big"
    "time"
)

// Generate RSA Keys: public and private pair
func GenerateRSAKeys() (*rsa.PrivateKey, error) {
    return rsa.GenerateKey(rand.Reader, 2048)
}

// Encrypt encrypts the message with the given public key
func Encrypt(pubKey *rsa.PublicKey, msg string) ([]byte, error) {
    hash := sha256.New()
    ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pubKey, []byte(msg), nil)
    return ciphertext, err
}

// Decrypt decrypts the ciphertext with the given private key
func Decrypt(privKey *rsa.PrivateKey, ciphertext []byte) (string, error) {
    hash := sha256.New()
    plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, privKey, ciphertext, nil)
    return string(plaintext), err
}

func calculateV(sigma int, x0, x1, encK []byte, senderPubKey rsa.PublicKey) []byte {
    x0Int := new(big.Int).SetBytes(x0)
    x1Int := new(big.Int).SetBytes(x1)
    encKInt := new(big.Int).SetBytes(encK)
    encKInt.Mod(encKInt, senderPubKey.N)

    v := new(big.Int)
    if sigma == 0 {
        v.Add(x0Int, encKInt)
    } else {
        v.Add(x1Int, encKInt)
    }
    return v.Bytes()
}

func senderRoutine(msgChan chan []byte, keyChan chan *rsa.PublicKey, receiveV chan []byte) {
    senderKeys, err := GenerateRSAKeys()
    if err != nil {
        fmt.Println("Error generating keys:", err)
        return
    }

    keyChan <- &senderKeys.PublicKey

    x0 := []byte("test0")
    x1 := []byte("test1")
    msgChan <- x0
    msgChan <- x1

    v := <-receiveV
    incomingVBytes := new(big.Int).SetBytes(v)
    preK0 := new(big.Int).Sub(incomingVBytes, new(big.Int).SetBytes(x0))
    preK1 := new(big.Int).Sub(incomingVBytes, new(big.Int).SetBytes(x1))

    k0, _ := Decrypt(senderKeys, preK0.Bytes())
    k1, _ := Decrypt(senderKeys, preK1.Bytes())
    fmt.Println("Decrypted k0:", k0)
    fmt.Println("Decrypted k1:", k1)
}

func receiverRoutine(msgChan chan []byte, keyChan chan *rsa.PublicKey, sendV chan []byte) {
    senderPubKey := <-keyChan
    tx0 := <-msgChan
    tx1 := <-msgChan

    k := "test2"
    encK, _ := Encrypt(senderPubKey, k)
    sigma := 0

    v := calculateV(sigma, tx0, tx1, encK, *senderPubKey)
    sendV <- v
}

func main() {
    msgChan := make(chan []byte, 2)
    keyChan := make(chan *rsa.PublicKey)
    receiveV := make(chan []byte)

    go senderRoutine(msgChan, keyChan, receiveV)
    go receiverRoutine(msgChan, keyChan, receiveV)

    time.Sleep(1 * time.Second) // Wait for goroutines to finish
}
