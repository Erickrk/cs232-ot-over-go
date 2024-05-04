/*
  Can we send messages more than once?
  Final implemententation
  To run: go run main.go
*/

package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "fmt"
    "math/big"
    "time"
    "strings"
    "sync"
)

/*
    FIRST PHASE:
        Setup: Allow the sender to initialize the protocol with two messages, M0M0 and M1M1. 
        a) Generates key pair
        b) Sender encrypts the two mesages with?
    SECOND PHASE: 
        Transfer: Implement the OT protocol such that the receiver can choose which message
        to receive (M0M0 or M1M1) without revealing their choice to the sender. Similarly,
        ensure the sender cannot determine which message was transferred. 
        a) Chooses the message to receive
        b) Decrypts the result
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
/*
    OAEP:  Optimal Asymmetric Encryption Padding
    In RSA-OAEP, the message is not directly encrypted with the RSA algorithm.
    Instead, the message is first padded with some additional data. 
    This padding includes a hash of the message, some random data, and a hash of that random data. 
    The padded message is then encrypted with the RSA algorithm.
    rsa.EncryptOAEP function works with byte slices, not strings, thus we have to convert msg.
*/ 
func Encrypt(pubKey *rsa.PublicKey, msg string) ([]byte, error) {
    hash := sha256.New()
    ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pubKey, []byte(msg), nil)
    if err != nil {
        return nil, err
    }
    return ciphertext, err
}

// Decrypt decrypts the ciphertext with the given private key
func Decrypt(privKey *rsa.PrivateKey, ciphertext []byte) (string, error) {
    hash := sha256.New()
    plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, privKey, ciphertext, nil)
    if err != nil {
        return "", err
    }
    return string(plaintext), nil
}

func generateRandomBytes() ([]byte, error) {
    x := make([]byte, 16)
    _, err := rand.Read(x)
    if err != nil {
        fmt.Println("Error generating random value:", err)
        return nil, err
    }
    return x, nil
}

/*Sender steps*/
func senderRoutine(msgChan chan []byte, keyChan chan *rsa.PublicKey, receiveV chan []byte) {
    senderKeys, err := GenerateRSAKeys()
    if err != nil {
        fmt.Println("Error generating keys:", err)
        return
    }
    fmt.Println(time.Now().UnixNano()/int64(time.Millisecond), "Receiver RSA keys generated")

    // Generates two random messages and sends them to the channel + key
    fmt.Println(time.Now().UnixNano()/int64(time.Millisecond), "Sender sending random messages messages and Public Key")
    keyChan <- &senderKeys.PublicKey // @TODO is this ok to be a pointer?
    //x0 := []byte("test0")
    //x1 := []byte("test1")
    x0, _ := generateRandomBytes()
    x1, _ := generateRandomBytes()
    msgChan <- x0
    msgChan <- x1

    // Sender receives v and decrypts
    v := <-receiveV
    incomingVBytes := new(big.Int).SetBytes(v)
    preK0 := new(big.Int).Sub(incomingVBytes, new(big.Int).SetBytes(x0))
    preK1 := new(big.Int).Sub(incomingVBytes, new(big.Int).SetBytes(x1))

    k0, _ := Decrypt(senderKeys, preK0.Bytes())
    k1, _ := Decrypt(senderKeys, preK1.Bytes()) 

    // We need to convert k0 and k1 to a big.Int to perform operations
    k0BigInt := new(big.Int)
    k0BigInt.SetString(k0, 10) // 10 is the base
    k1BigInt := new(big.Int)
    k1BigInt.SetString(k1, 10)

    // Now we need to mod k0 and k1 with the public key N and then convert them to string
    k0Str := new(big.Int).Mod(k0BigInt, new(big.Int).Set(senderKeys.PublicKey.N)).String()
    k1Str := new(big.Int).Mod(k1BigInt, new(big.Int).Set(senderKeys.PublicKey.N)).String()

    // Sender creates the messages
    // Space is currently breaking the string, what is anoying for sending sets
    // It is possible to send something like [alex,mateo,joao]
    var m0, m1 string
    fmt.Println("Enter message 0:")
    fmt.Scanln(&m0)
    fmt.Println("Enter message 1:")
    fmt.Scanln(&m1)
    fmt.Println(time.Now().UnixNano()/int64(time.Millisecond), "Sender created messages")
    
    // messages zero and one prime
    m0p := []byte(m0 + k0Str)
    m1p := []byte(m1 + k1Str)
    fmt.Println(time.Now().UnixNano()/int64(time.Millisecond), "SENDER STEP 4: hid the messages")
    msgChan <- m0p
    msgChan <- m1p

}

// Receiver v calculation
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
/*Receiver steps*/
func receiverRoutine(msgChan chan []byte, keyChan chan *rsa.PublicKey, sendV chan []byte) {
    senderPubKey := <-keyChan
    tx0 := <-msgChan
    tx1 := <-msgChan
    fmt.Println("Random string 1:", tx0)
    fmt.Println("Random string 2:", tx1)
    fmt.Println("Sender's Public Key expoent:", senderPubKey.E) // @TODO: is this a constant value??
    fmt.Println("Sender's Public Key N:", senderPubKey.N)

    kBytes, _ := generateRandomBytes()
    k := string(kBytes)
    fmt.Println("Random string k:", k)

    encK, _ := Encrypt(senderPubKey, k)

    var sigma int
    fmt.Println("Choose sigma 0 or 1:") //  should check if value is valid
    fmt.Scanln(&sigma)
    fmt.Println(time.Now().UnixNano()/int64(time.Millisecond), "Receiver choose sigma", sigma)

    v := calculateV(sigma, tx0, tx1, encK, *senderPubKey)
    sendV <- v
    // Receiver receives the messages
    m0r := <-msgChan
    m1r := <-msgChan
    kInt := new(big.Int)
    kInt.SetString(k, 10)

    // Receiver retrieves the messages
    msg := new(big.Int)
    if sigma == 0 {
        m0rInt := new(big.Int).SetBytes(m0r)
        msg.Sub(m0rInt, kInt)
    } else {
        m1rInt := new(big.Int).SetBytes(m1r)
        msg.Sub(m1rInt, kInt)
    }

    // Convert the message to a string
    msgBytes := big.NewInt(0).Set(msg).Bytes()
    msgStr := string(msgBytes)
    msgStr = strings.TrimRight(msgStr, "0") // string was finishing with zero so we need to remove it

    fmt.Println(time.Now().UnixNano()/int64(time.Millisecond), "REC STEP 4: retrieves the message ", msgStr)
}

func main() {
    startTime := time.Now()
    fmt.Println(time.Now().UnixNano()/int64(time.Millisecond), "Starting the protocol simulation")

    // Create a channel to send the random numbers and key
    // Channels are FIFO
    msgChan := make(chan []byte) // Removed buffer, does it break?
    keyChan := make(chan *rsa.PublicKey)
    receiveV := make(chan []byte)

    var wg sync.WaitGroup
    wg.Add(2) // Add the number of goroutines to wait for

    go func() {
        senderRoutine(msgChan, keyChan, receiveV)
        wg.Done() // Decrease the WaitGroup counter when the goroutine finishes
    }()

    go func() {
        receiverRoutine(msgChan, keyChan, receiveV)
        wg.Done() // Decrease the WaitGroup counter when the goroutine finishes
    }()

    wg.Wait() // Wait for all goroutines to finish
    // Used to run in around 100 ms before User Input
    // time metrics could be better without counting IO time
    endTime := time.Now()
    fmt.Println("Total execution time in milliseconds:", endTime.Sub(startTime).Milliseconds())
}


