PROTO_PATH=./
GO_OUT_DIR=$(shell go env GOPATH)/src

.PHONY: all clean

all: *.proto
	@echo "Using Proto Path: ${PROTO_PATH}"
	@echo "Using Go Out Directory: ${GO_OUT_DIR}"
	protoc $? -I${PROTO_PATH} --go_out=:${GO_OUT_DIR}

clean:
	@find .. -name "*.pb.go" -delete
	@echo "Cleaned all protobuf builds"
