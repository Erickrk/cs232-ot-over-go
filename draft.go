/*
	@TODO: implement channels to allow communication and key exchange between peers

*/

package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "fmt"
    "time"
)

// Diffie-Hellman for key exchange


// Peer struct to hold details of each participant
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
    key, err := rsa.GenerateKey(rand.Reader, 2048)
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
    ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pubKey, []byte(msg), label)
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
    plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, privKey, ciphertext, label)
    if err != nil {
        return "", err
    }
    return string(plaintext), nil
}

func main() {
    startTime := time.Now()

    fmt.Println(time.Now().UnixNano()/int64(time.Millisecond), "Starting the protocol simulation")

    receiver, _ := GenerateRSAKeys()
    fmt.Println(time.Now().UnixNano()/int64(time.Millisecond), "Receiver RSA keys generated")

    obliviousKey, _ := GenerateRSAKeys()
    fmt.Println(time.Now().UnixNano()/int64(time.Millisecond), "Receiver RSA keys generated")

    sigma := 1
    fmt.Println(time.Now().UnixNano()/int64(time.Millisecond), "Receiver chose sigma:", sigma)

    var pk0, pk1 *rsa.PublicKey
    if sigma == 0 {
        pk0 = &receiver.PublicKey
        pk1 = &obliviousKey.PublicKey
    } else {
        pk0 = &obliviousKey.PublicKey
        pk1 = &receiver.PublicKey
    }
    fmt.Println(time.Now().UnixNano()/int64(time.Millisecond), "Public keys assigned")

    m0 := "Hello, world!"
    m1 := "Goodbye, world!"
    fmt.Println(time.Now().UnixNano()/int64(time.Millisecond), "Sender created messages")

    c0, _ := Encrypt(pk0, m0)
    c1, _ := Encrypt(pk1, m1)
    fmt.Println(time.Now().UnixNano()/int64(time.Millisecond), "Sender encrypted messages")

    var decryptedMessage string
    if sigma == 0 {
        decryptedMessage, _ = Decrypt(receiver, c0)
    } else {
        decryptedMessage, _ = Decrypt(receiver, c1)
    }
    fmt.Println(time.Now().UnixNano()/int64(time.Millisecond), "Receiver decrypted the desired message")

    fmt.Println(time.Now().UnixNano()/int64(time.Millisecond), "Decrypted message:", decryptedMessage)
    
    endTime := time.Now()
    fmt.Println("Total execution time in milliseconds:", endTime.Sub(startTime).Milliseconds())

}