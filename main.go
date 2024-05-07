/*
  ********************************************************************************
  Final implemententation of the Practical 1 out of 2 OT protocol for CS232
  Goal: receiver can choose which message to receive without revealing their choice to the sender
    and the sender cannot determine which message was read by receiver.
  Prints are for a semi-honest party, showing what they could read if curious.
  Terminal output was used over comments so we can see the flow of the protocol while running.
  Used to run in around 100 ms before User Input
  @todos:
  Can the protocol run more than once?
  make prints as debug
  time metrics could be better without counting IO time
  ********************************************************************************
  To run: go run main.go
*/

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"math/big"
	"sync"
	"time"
)

/*
   @todo: FIX THIS
   FIRST PHASE:
       Setup: Allow the sender to initialize the protocol with two messages, M0M0 and M1M1.
       a) Generates key pair
       b) Sender encrypts the two mesages with publick key
   SECOND PHASE:
       Transfer: Implement the OT protocol such that the receiver can choose which message
       to receive (M0M0 or M1M1) without revealing their choice to the sender. Similarly,
       ensure the sender cannot determine which message was transferred.
       a) Chooses the message to receive
       b) Decrypts the result
*/

/*
  ********************************************************************************
                                    Encryption functions
  ********************************************************************************
*/

// Generate RSA Keys: public and private pair
// Rand.reader is a global, shared instance of a cryptographically secure random number generator
// 2048 is the key size
func GenerateRSAKeys() (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return key, nil
}

/*
OAEP:  Optimal Asymmetric Encryption Padding
In RSA-OAEP, the message is not directly encrypted with the RSA algorithm.
Instead, the message is first padded with some additional data.
This padding includes a hash of the message, some random data, and a hash of that random data.
The padded message is then encrypted with the RSA algorithm.

rsa.EncryptOAEP function works with byte slices, not strings, thus we have to convert msg.

"The message must be no longer than the length of the public modulus minus twice the
hash length, minus a further 2." - Function documentation
The public modulus is 2048 bits, or 256 bytes, so the message must be no longer than 256 - 2*32 - 2 = 190 bytes.
@todo: what if is bigger?
*/
func Encrypt(pubKey *rsa.PublicKey, msg string) ([]byte, error) {
	hash := sha256.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pubKey, []byte(msg), nil)
	if err != nil {
		return nil, err
	}
	return ciphertext, err
}

/*
This function doesn't accept to be applied on values that are not
reconizable as a valid ciphertext. So, I've decided to return a random value in case it fails.
In this case, the user won't be able to notice an empty string returned by the function and thus see
which message was chosen by the receiver.
*/
func Decrypt(privKey *rsa.PrivateKey, ciphertext []byte) (string, error) {
	hash := sha256.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, privKey, ciphertext, nil)
	if err != nil {
		fdata, _ := generateRandomBytes()
		return string(fdata), err
	}
	return string(plaintext), nil
}

// We need to generate random bytes to use as messages/placeholders
func generateRandomBytes() ([]byte, error) {
	x := make([]byte, 16)
	_, err := rand.Read(x)
	if err != nil {
		fmt.Println("Error generating random value:", err)
		return nil, err
	}
	return x, nil
}

/*
********************************************************************************

	Sender steps

********************************************************************************
*/
func senderRoutine(msgChan chan []byte, keyChan chan *rsa.PublicKey, receiveV chan []byte) {
	senderKeys, err := GenerateRSAKeys()
	if err != nil {
		fmt.Println("Error generating keys:", err)
		return
	}
	fmt.Println("SENDER STEP 1: generated RSA key-pair")

	keyChan <- &senderKeys.PublicKey
	x0, _ := generateRandomBytes()
	x1, _ := generateRandomBytes()
	msgChan <- x0
	msgChan <- x1
	fmt.Println("SENDER STEP 2: Generated random messages. Now sending random messages and Public Key to Receiver", x0, x1)

	// Sender receives v and decrypts
	v := <-receiveV
	// fmt.Println("SENDER STEP 2.5: Received v from Receiver", v)
	// v - x0 and v - x1
	// values must be converted to big int to perform operations
	incomingVBytes := new(big.Int).SetBytes(v)
	preK0 := new(big.Int).Sub(incomingVBytes, new(big.Int).SetBytes(x0))
	preK1 := new(big.Int).Sub(incomingVBytes, new(big.Int).SetBytes(x1))

	// ciphertext should be byte slices
	preK0bytes := preK0.Bytes()
	preK1bytes := preK1.Bytes()
	//fmt.Println("DEBUG: preK0:", len(preK0bytes))
	//fmt.Println("DEBUG: preK1:", len(preK1bytes))

	// Can't have error handling so we don't leak information
	// k0^d and k1^d
	k0, _ := Decrypt(senderKeys, preK0bytes)
	k1, _ := Decrypt(senderKeys, preK1bytes)

	//fmt.Println("DEBUG: k0:", k0)
	//fmt.Println("DEBUG: k1:", k1)

	// Again, we need to convert k0 and k1 to a big.Int to perform operations
	k0Slice := []byte(k0)
	k0BigInt := new(big.Int).SetBytes(k0Slice)
	k1Slice := []byte(k1)
	k1BigInt := new(big.Int).SetBytes(k1Slice)

	// Now we need to mod k0 and k1 with the public key N and then convert them to string
	// k0%N and k1%N
	k0Str := new(big.Int).Mod(k0BigInt, new(big.Int).Set(senderKeys.PublicKey.N))
	k1Str := new(big.Int).Mod(k1BigInt, new(big.Int).Set(senderKeys.PublicKey.N))

	// fmt.Println("DEBUG: k0:", k0)
	// fmt.Println("DEBUG: k1:", k1)
	// fmt.Println("DEBUG: k0BIG:", k0BigInt)
	// fmt.Println("DEBUG: k1BIG:", k1BigInt)
	// fmt.Println("DEBUG: k0Str:", k0Str)
	// fmt.Println("DEBUG: k1Str:", k1Str)

	fmt.Printf("SENDER STEP 3: Decrypts the two possible ks %v and %v\n", k0Str, k1Str)

	// Sender inputs the messages
	// Space is currently breaking the string, what is anoying for sending sets
	// It is possible to send something like [alex,mateo,joao]
	var m0, m1 string
	fmt.Println("SENDER: Enter message 0:")
	fmt.Scanln(&m0)
	fmt.Println("SENDER: Enter message 1:")
	fmt.Scanln(&m1)

	// messages zero and one prime
	// Converting to byte slice and then big.Int to perform operations
	m0Big := new(big.Int).SetBytes([]byte(m0))
	m1Big := new(big.Int).SetBytes([]byte(m1))
	m0p := new(big.Int).Add(m0Big, k0Str).Bytes()
	m1p := new(big.Int).Add(m1Big, k1Str).Bytes()

	fmt.Println("Message 0 Prime:", m0p)
	fmt.Println("Message 1 Prime:", m1p)

	msgChan <- m0p
	msgChan <- m1p
	fmt.Printf("SENDER STEP 4: hid the messages 0: %v and 1:%v now is sending them on the channel\n", m0p, m1p)
}

/*
  ********************************************************************************
                            Sender steps end
  ********************************************************************************
*/

/*
  ********************************************************************************
                            Receiver steps
  ********************************************************************************
*/
// Receiver v calculation
func calculateV(sigma int, x0, x1, encK []byte, senderPubKey rsa.PublicKey) []byte {
	x0Int := new(big.Int).SetBytes(x0)
	x1Int := new(big.Int).SetBytes(x1)
	encKInt := new(big.Int).SetBytes(encK)
	encKInt.Mod(encKInt, senderPubKey.N)

	//fmt.Println("x0Int:", x0Int)
	//fmt.Println("x1Int:", x1Int)
	//fmt.Println("encKInt:", encKInt)

	v := new(big.Int)
	if sigma == 0 {
		v = v.Add(x0Int, encKInt)
		//fmt.Println("Performed the add to 0:", v)
	} else {
		v = v.Add(x1Int, encKInt)
		//fmt.Println("Performed the add to 1:", v)
	}
	return v.Bytes()
}

// @todo: continue review from here
func receiverRoutine(msgChan chan []byte, keyChan chan *rsa.PublicKey, sendV chan []byte) {
	senderPubKey := <-keyChan
	tx0 := <-msgChan
	tx1 := <-msgChan
	fmt.Printf("RECEIVER STEP 0: received random messages and Public Key\nRandom string 1: %v\nRandom string 2: %v\nSender's Public Key exponent: %v\nSender's Public Key N: %v\n", tx0, tx1, senderPubKey.E, senderPubKey.N)

	// Receiver chooses which messager wants to see
	var sigma int
	fmt.Println("Choose sigma 0 or 1:")
	_, err := fmt.Scanln(&sigma)
	if err != nil || (sigma != 0 && sigma != 1) {
		fmt.Println("Invalid value for sigma. Please choose either 0 or 1.")
		return
	}
	fmt.Println("Receiver chose sigma", sigma)

	kBytes, _ := generateRandomBytes()
	k := string(kBytes)
	fmt.Println("\nRECEIVER STEP 1: Generated random message k:", k)

	encK, err := Encrypt(senderPubKey, k)
	if err != nil {
		fmt.Println("Error encrypting message:", err)
		return
	}
	fmt.Println("RECEIVER STEP 2: Encrypted random message k:", encK)

	v := calculateV(sigma, tx0, tx1, encK, *senderPubKey)
	sendV <- v

	fmt.Printf("RECEIVER STEP 3: Calculated v %v and now is sending on the channel\n", v)

	// Receiver receives the messages
	m0r := <-msgChan
	m1r := <-msgChan
	kInt := new(big.Int)
	kInt.SetBytes(kBytes)

	// Receiver retrieves the messages
	msg0 := new(big.Int)
	msg1 := new(big.Int)

	m0rInt := new(big.Int).SetBytes(m0r)
	msg0.Sub(m0rInt, kInt)
	m1rInt := new(big.Int).SetBytes(m1r)
	msg1.Sub(m1rInt, kInt)

	fmt.Println("DEBUG: kInt:", kInt)
	fmt.Println("DEBUG: m0rInt:", m0rInt)
	fmt.Println("DEBUG: msg0:", msg0)
	fmt.Println("DEBUG: m1rInt:", m1rInt)
	fmt.Println("DEBUG: msg1:", msg1)

	// Convert the messages to strings
	msg0Bytes := big.NewInt(0).Set(msg0).Bytes()
	msg0Str := string(msg0Bytes)
	//msg0Str = strings.TrimRight(msg0Str, "0")

	msg1Bytes := big.NewInt(0).Set(msg1).Bytes()
	msg1Str := string(msg1Bytes)
	// msg1Str = strings.TrimRight(msg1Str, "0")

	fmt.Printf("RECEIVER STEP 4: Retrieved the message %v for sigma %v\n", msg0Str, sigma)
	fmt.Printf("CURIOUS RECEIVER STEP 5: Retrieved the message %v for sigma %v\n", msg1Str, 1-sigma)

}

/*
********************************************************************************

	Receiver steps end

********************************************************************************
*/
func main() {
	startTime := time.Now()
	fmt.Println("Starting the protocol simulation")

	// Create a channel to send the random numbers and key
	// Channels are FIFO
	msgChan := make(chan []byte)
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
	endTime := time.Now()
	fmt.Println("Total execution time in milliseconds:", endTime.Sub(startTime).Milliseconds())
	// Maybe it could wait for user input here?

}
