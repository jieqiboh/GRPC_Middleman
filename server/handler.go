package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"server/constants"

	"log"
	"server/model"
	"server/mychacha20"
)

type server struct {
	model.UnimplementedMiddlemanServer
}

// PSI implements PSI on MiddleMan
func (s *server) PSI(ctx context.Context, in *model.Request) (*model.Response, error) {
	secretKey, err := mychacha20.GenerateChaCha20Key()
	if err != nil {
		return &model.Response{}, nil
	}
	secretNonce, err := mychacha20.GenerateChaCha20Nonce()
	if err != nil {
		return &model.Response{}, nil
	}

	//Asynchronously make HTTP requests to API Gateway asking for intersection of microsvc data
	//If invalid params, immediately terminate entire operation
	log.Printf("Received SvcInfo: %v", in.GetSvcInfo())
	serviceInfoList := extractRequestSvcInfo(in)
	log.Printf("Extracted SvcInfo:")
	log.Print(serviceInfoList)
	APIGatewayURL := constants.APIGATEWAY_URL
	response, err := makePSIReqToAPIGateway(APIGatewayURL, serviceInfoList)
	defer response.Body.Close()
	microsvcIntersection, err := extractResponseAsListBytes(response)
	if err != nil {
		return nil, err
	}

	//Encrypt data from client
	err = mychacha20.Encrypt(secretKey, secretNonce, in.EncryptedElems)
	if err != nil {
		return &model.Response{}, nil
	}

	err = mychacha20.Encrypt(secretKey, secretNonce, microsvcIntersection)
	if err != nil {
		return &model.Response{}, nil
	}

	return &model.Response{DoubleEncryptedElems: in.EncryptedElems, EncryptedServerElems: microsvcIntersection}, nil
}

// HELPER METHODS
// Used to write code for overarching steps of handlers.
func extractRequestSvcInfo(in *model.Request) [][]string {
	serviceInfoList := make([][]string, len(in.SvcInfo))
	for i, info := range in.SvcInfo {
		serviceInfoList[i] = []string{info.ServiceName, info.MethodName}
	}

	return serviceInfoList
}

// Response body should be a json list containing intersection
func makePSIReqToAPIGateway(serverURL string, serviceInfoList [][]string) (*http.Response, error) {
	// Convert serviceInfoList to JSON
	jsonData, err := json.Marshal(serviceInfoList)
	if err != nil {
		return nil, err
	}

	// Create an HTTP POST request with the JSON data
	req, err := http.NewRequest("POST", serverURL+"/PSI", bytes.NewReader(jsonData))
	if err != nil {
		return nil, err
	}

	// Set the Content-Type header
	req.Header.Set("Content-Type", "application/json")

	// Create an HTTP client
	client := &http.Client{}

	// Send the HTTP request
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		fmt.Println("HTTP request failed with status code:", resp.StatusCode)
		return nil, nil
	}
	fmt.Println("Svc Intersection Req to API Gateway successful")

	return resp, nil
}

func extractResponseAsListBytes(resp *http.Response) ([][]byte, error) {
	// Check if the response status code is OK (200)
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("HTTP request failed with status code: " + resp.Status)
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Unmarshal the JSON response into a []string
	var stringList []string
	if err := json.Unmarshal(body, &stringList); err != nil {
		return nil, err
	}
	fmt.Print("extractResponseAsListBytes stringlist: ")
	fmt.Println(stringList)

	// Convert each string to []byte and append it to byteList
	var byteList [][]byte
	for _, str := range stringList {
		byteList = append(byteList, []byte(str))
	}

	return byteList, nil
}
