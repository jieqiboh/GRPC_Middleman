package main

import (
	"fmt"
	"google.golang.org/grpc"
	"log"
	"net"
	"server/model"
)

func main() {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", 7999))
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
