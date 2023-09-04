package main

import (
	"client/constants"
	"context"
	"encoding/csv"
	"fmt"
	"github.com/rs/cors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"io"
	"log"
	"net/http"
	"server/model"
	"server/mychacha20"
	"strings"
)

func main() {
	//Create a HTTP server with a route to handle the "/PSI" endpoint
	mux := http.NewServeMux()
	mux.HandleFunc("/", PSIHandler)
	handler := cors.Default().Handler(mux)

	//Start the server on port 3001
	port := ":" + constants.OWN_PORT

	fmt.Printf("Server listening on %s\n", port)
	log.Fatal(http.ListenAndServe(port, handler))
}

func PSI(c model.MiddlemanClient, clientData [][]byte, serviceinfo []*model.Request_ServiceInfo) (int, error) {
	//Generate secret keys and nonces for encryption
	secretKey, err := mychacha20.GenerateChaCha20Key()
	if err != nil {
		return -1, err
	}
	secretNonce, err := mychacha20.GenerateChaCha20Nonce()
	if err != nil {
		return -1, err
	}

	mychacha20.Encrypt(secretKey, secretNonce, clientData)

	// Contact the server and print out its response.
	ctx := context.Background()
	r, err := c.PSI(ctx, &model.Request{EncryptedElems: clientData, SvcInfo: serviceinfo})
	if err != nil {
		fmt.Println(err.Error())
		return -1, err
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

	return commonCount, nil
}

// Creates the necessary structs
func PSIHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the multipart form data
	err := r.ParseMultipartForm(10 << 20) // Set a reasonable max memory limit for form data (10MB)
	if err != nil {
		http.Error(w, "Unable to parse form", http.StatusBadRequest)
		return
	}

	// Get the upstreamurl from the form
	upstreamurl := r.Form["upstreamurl"][0]

	// Get the CSV file from the form
	file, _, err := r.FormFile("csvfile")
	if err != nil {
		http.Error(w, "Unable to get CSV file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Create a CSV reader
	csvReader := csv.NewReader(file)
	var records []string

	// Read and process the CSV data
	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, "Error reading CSV: "+err.Error(), http.StatusInternalServerError)
			return
		}
		records = record
	}

	svcinfo := r.Form["svcinfo"]
	// Process the uploaded CSV file and list of names
	// (You can implement your processing logic here)
	var clientData [][]byte

	for _, str := range records {
		clientData = append(clientData, []byte(str))
	}

	// Split the input string by spaces
	svcinfo = strings.Split(svcinfo[0], " ")

	// Iterate through svcinfo and create serviceinfo []*model.Request_ServiceInfo
	var serviceinfo []*model.Request_ServiceInfo
	for i := 0; i < len(svcinfo); i += 2 {
		serviceinfo = append(serviceinfo, &model.Request_ServiceInfo{ServiceName: svcinfo[i], MethodName: svcinfo[i+1]})
	}

	conn, err := grpc.Dial(upstreamurl, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		log.Printf("did not connect: %v", err)
		return
	}
	defer conn.Close()

	c := model.NewMiddlemanClient(conn)

	commonCount, err := PSI(c, clientData, serviceinfo) //-1 if error
	if err != nil {
		// Respond with a success message
		log.Printf("could not do PSI: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Respond with a success message
	w.WriteHeader(http.StatusOK)
	// Convert the integer to a string and write it to the response body
	w.Write([]byte(fmt.Sprintf("%d", commonCount)))
}
