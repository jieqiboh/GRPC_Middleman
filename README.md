## GRPC MIDDLEMAN
protoc --go_out=. --go_opt=paths=source_relative \
--go-grpc_out=. --go-grpc_opt=paths=source_relative \
model/server.proto

Remember to modify the package names of the generated files in /model !