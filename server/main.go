package main

import (
	"fmt"
	"google.golang.org/grpc"
	"log"
	"net"
	"os"
	"server/model"
	"strconv"
)

func main() {
	GPRC_PORT := os.Args[1]

	// Convert the string to an integer
	port, err := strconv.Atoi(GPRC_PORT)
	if err != nil {
		fmt.Printf("Error converting port to integer: %v\n", err)
		os.Exit(1)
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	model.RegisterMiddlemanServer(s, &server{})
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
