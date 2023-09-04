# GRPC MIDDLEMAN
Contains the implementation for the GRPC Client that doubles as a server, as well as the GRPC Middleman

### Additional Notes
protoc --go_out=. --go_opt=paths=source_relative \
--go-grpc_out=. --go-grpc_opt=paths=source_relative \
model/server.proto

Remember to modify the package names of the generated files in /model !