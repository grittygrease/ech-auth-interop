# Multi-stage Docker build for NSS ECH Auth testing
# 
# Stage 1: Build NSS with ECH Auth patch
# Stage 2: Run Python parser on test vectors

FROM ubuntu:22.04 as nss-builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    mercurial ninja-build gyp zlib1g-dev libnspr4-dev \
    pkg-config gcc g++ make python3 patch \
    && rm -rf /var/lib/apt/lists/*

# Clone NSS 3.120
WORKDIR /build
RUN hg clone https://hg.mozilla.org/projects/nss nss-repo
WORKDIR /build/nss-repo
RUN hg update NSS_3_120_RTM

# Copy patch file
COPY nss/nss_echauth.patch /build/

# Apply patch
RUN patch -p1 < /build/nss_echauth.patch

# Build NSS with ECH Auth
RUN BUILD_OPT=1 USE_64=1 ./build.sh --system-nspr

# Stage 2: Test runner
FROM ubuntu:22.04

# Install Python
RUN apt-get update && apt-get install -y python3 && rm -rf /var/lib/apt/lists/*

# Copy NSS build (proves compilation succeeded)
COPY --from=nss-builder /build/nss-repo/out/Debug /nss/out/Debug

# Copy test vectors and parser
COPY test-vectors /test/test-vectors/
COPY nss/parse_test_vectors.py /test/

WORKDIR /test
CMD ["python3", "parse_test_vectors.py"]
