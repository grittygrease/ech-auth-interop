# ECH Auth NSS Build
#
# Prerequisites:
#   - NSS built with: ./build.sh
#   - NSS_DIR pointing to NSS dist directory

NSS_DIR ?= /usr/local/nss
NSPR_DIR ?= /usr/local/nspr

CC = clang
CFLAGS = -Wall -g -O0 \
         -I$(NSS_DIR)/include/nss \
         -I$(NSPR_DIR)/include/nspr

LDFLAGS = -L$(NSS_DIR)/lib -L$(NSPR_DIR)/lib \
          -lssl3 -lnss3 -lnssutil3 -lplc4 -lplds4 -lnspr4

TARGETS = echauth_client

.PHONY: all clean test

all: $(TARGETS)

# ECH Auth implementation (would be compiled into NSS)
tls13echauth.o: tls13echauth.c tls13echauth.h
	$(CC) $(CFLAGS) -c $< -o $@

# Test client
echauth_client: echauth_client.c tls13echauth.o tls13echauth.h
	$(CC) $(CFLAGS) $< tls13echauth.o -o $@ $(LDFLAGS)

clean:
	rm -f $(TARGETS) *.o

# Test against Go server
test: echauth_client
	@echo "Starting Go server in background..."
	cd ../go && go run . -server -port 8443 &
	sleep 2
	@echo "Running ECH Auth client..."
	./echauth_client -h localhost -p 8443 -e ../test-vectors/echconfig.bin \
	    -t $$(cat ../test-vectors/spki_hash.txt)
	@echo "Stopping Go server..."
	pkill -f "go run . -server" || true

# Generate test vector from Rust
test-vector:
	mkdir -p ../test-vectors
	cd ../rust && cargo run --bin gen-test-vector > ../test-vectors/vector.json
	@echo "Test vector generated"
