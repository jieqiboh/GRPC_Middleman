package main

import (
	"context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"log"
	"server/model"
	"server/mychacha20"
)

var (
	addr = "localhost:7999"
)

func main() {
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	c := model.NewMiddlemanClient(conn)

	testPSI(c)

}

func testPSI(c model.MiddlemanClient) {
	//Generate secret keys and nonces for encryption
	secretKey, err := mychacha20.GenerateChaCha20Key()
	if err != nil {
		panic(err)
	}
	secretNonce, err := mychacha20.GenerateChaCha20Nonce()
	if err != nil {
		panic(err)
	}

	//Client input here
	clientData := [][]byte{[]byte("Lyle"), []byte("Jane"), []byte("Jack"), []byte("Charles")}
	mychacha20.Encrypt(secretKey, secretNonce, clientData)
	serviceinfo := []*model.Request_ServiceInfo{
		&model.Request_ServiceInfo{ServiceName: "PosterService", MethodName: "getuniqueusernames"},
		&model.Request_ServiceInfo{ServiceName: "ViewerService", MethodName: "getuniqueviewernames"},
	}

	// Contact the server and print out its response.
	// ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	// defer cancel()
	ctx := context.Background()
	r, err := c.PSI(ctx, &model.Request{EncryptedElems: clientData, SvcInfo: serviceinfo})
	if err != nil {
		log.Fatalf("could not do PSI: %v", err)
	}

	//Client decrypts double encrypted client data with own key
	mychacha20.Decrypt(secretKey, secretNonce, r.DoubleEncryptedElems)

	// Client compares elements in r.DoubleEncryptedElems with r.EncryptedServerElems
	// First find smaller set, then iterate through it and create a hashmap
	// Then for each element in the larger set, check if it exists
	elems := make(map[string]bool)
	// Populate the map with elements from slice A
	for _, element := range r.DoubleEncryptedElems {
		elems[string(element)] = true
	}

	// Count the common elements in slice B
	commonCount := 0
	for _, element := range r.EncryptedServerElems {
		if elems[string(element)] {
			commonCount++
		}
	}

	log.Printf("Intersection Size: %d\n", commonCount)
}
