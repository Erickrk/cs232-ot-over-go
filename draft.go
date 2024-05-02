/*
    @TODO: all values should be []bytes
	@TODO: implement channels to allow communication and key exchange between peers
    // Diffie-Hellman for key exchange
    // mmo OT
*/

package main

import (
	//"bytes"
    "math/big"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"time"
)


// Peer struct to hold details of each participant
// @todo: we should have one sender and one receiver
type Peer struct {
    Name  string
    Mode  string // "sender" or "receiver"
    Keys  *rsa.PrivateKey
    PubKey0 *rsa.PublicKey // Public key for first message or pk0
    PubKey1 *rsa.PublicKey // Public key for second message or pk1
}

/*
    Setup: Allow the sender to initialize the protocol with two messages, M0M0 and M1M1. 
    a) Generates key pair
    b) Sender encrypts the two mesages with?
*/
// Generate RSA Keys: public and private pair
func GenerateRSAKeys() (*rsa.PrivateKey, error) {
	// Rand.reader is a global, shared instance of a cryptographically secure random number generator
	// 2048 is the key size
    key, err := rsa.GenerateKey(crand.Reader, 2048)
    if err != nil {
        return nil, err
    }
    return key, nil
}

// Encrypt encrypts the message with the given public key
func Encrypt(pubKey *rsa.PublicKey, msg string) ([]byte, error) {
    label := []byte("") // Optional context to the message
    hash := sha256.New()
	/*
	 OAEP:  Optimal Asymmetric Encryption Padding
	 In RSA-OAEP, the message is not directly encrypted with the RSA algorithm.
	 Instead, the message is first padded with some additional data. 
	 This padding includes a hash of the message, some random data, and a hash of that random data. 
	 The padded message is then encrypted with the RSA algorithm.
	 rsa.EncryptOAEP function works with byte slices, not strings, thus we have to convert msg.
	*/ 
    ciphertext, err := rsa.EncryptOAEP(hash, crand.Reader, pubKey, []byte(msg), label)
    if err != nil {
        return nil, err
    }
    return ciphertext, nil
}


/*
    Transfer: Implement the OT protocol such that the receiver can choose which message
    to receive (M0M0 or M1M1) without revealing their choice to the sender. Similarly,
    ensure the sender cannot determine which message was transferred. 
    a) Chooses the message to receive
    b) Decrypts the result
*/

// Decrypt decrypts the ciphertext with the given private key
func Decrypt(privKey *rsa.PrivateKey, ciphertext []byte) (string, error) {
    label := []byte("")
    hash := sha256.New()
    plaintext, err := rsa.DecryptOAEP(hash, crand.Reader, privKey, ciphertext, label)
    if err != nil {
        return "", err
    }
    return string(plaintext), nil
}

/*
 Receiver v generation
*/
func calculateV(sigma int, x0, x1, encK []byte, senderPubKey rsa.PublicKey) []byte {
    x0Int := new(big.Int).SetBytes(x0)
    x1Int := new(big.Int).SetBytes(x1)
    encKInt := new(big.Int).SetBytes(encK)

    v := new(big.Int)
    if sigma == 0 {
        v.Add(x0Int, encKInt)
    } else {
        v.Add(x1Int, encKInt)
    }
    v.Mod(v, senderPubKey.N)
    return v.Bytes()
}

func main() {
    //startTime := time.Now()

    fmt.Println(time.Now().UnixNano()/int64(time.Millisecond), "Starting the protocol simulation")

    // Sender routine
    sender, _ := GenerateRSAKeys()
    fmt.Println(time.Now().UnixNano()/int64(time.Millisecond), "Receiver RSA keys generated")
    // Create a channel to send the random numbers and key
    // Channels are FIFO
    msgChan := make(chan []byte)
    keyChan := make(chan rsa.PublicKey)

    
    // Generates two random messages and
    // sends them to the channel + key
    go func() {
        x0 := []byte("test0")
        x1 := []byte("test1")
        msgChan <- x0
        msgChan <- x1
        // Send the sender's public key
        keyChan <- sender.PublicKey
    }()

    /*Receiver*/
    // Receive the random numbers and public key from the channel
    x0 := <-msgChan
    x1 := <-msgChan
    senderPubKey := <-keyChan

    fmt.Println("Random string 1:", x0)
    fmt.Println("Random string 2:", x1)
    fmt.Println("Sender's Public Key expoent:", senderPubKey.E) // is this a constant value??
    fmt.Println("Sender's Public Key N:", senderPubKey.N)

    k := "test2"
    fmt.Println("Random string k:", k)
    encK, _ := Encrypt(&senderPubKey, k)
    // Chooses which message to receive
    sigma := 1
    fmt.Println(time.Now().UnixNano()/int64(time.Millisecond), "Receiver chose sigma:", sigma)

    v := calculateV(sigma, x0, x1, encK, senderPubKey)
    // Sends v to the sender
    msgChan <- v

    /*Sender receives v and decrypts*/
    // We need to change to big.Int to perform operations
    incomingV := new(big.Int).SetBytes(<-msgChan)
    preK0 := new(big.Int).Sub(incomingV, new(big.Int).SetBytes(x0))
    preK1 := new(big.Int).Sub(incomingV, new(big.Int).SetBytes(x1))

    k0, _ := Decrypt(sender, preK0.Bytes())
    k1, _ := Decrypt(sender, preK1.Bytes())

    k0BigInt := new(big.Int)
    k0BigInt.SetString(k0, 10) // 10 is the base

    k1BigInt := new(big.Int)
    k1BigInt.SetString(k1, 10) // 10 is the base


    k0 = new(big.Int).Mod(k0BigInt, &sender.PublicKey.N)
    k1 = new(big.Int).Mod(k1BigInt, sender.PublicKey.N)

    m0 := "Hello, world!"
    m1 := "Goodbye, world!"
    fmt.Println(time.Now().UnixNano()/int64(time.Millisecond), "Sender created messages")

    m0p := m0 + k0Str
    m1p := m1 + k1Str
    fmt.Println(time.Now().UnixNano()/int64(time.Millisecond), "Sender hid the messages")
    x0 := <-msgChan
    x1 := <-msgChan
  
    endTime := time.Now()
    fmt.Println("Total execution time in milliseconds:", endTime.Sub(startTime).Milliseconds())

}