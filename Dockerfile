# ---- build stage ----
FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake ninja-build build-essential pkg-config \
    libssl-dev \
    libpq-dev \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
 && cmake --build build


# ---- runtime stage ----
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates \
    libssl3 \
    libpq5 \
    postgresql-client \
    curl \
    dos2unix \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY --from=build /src /src

COPY docker/entrypoint.sh /entrypoint.sh
RUN dos2unix /entrypoint.sh && chmod +x /entrypoint.sh

EXPOSE 3434
ENTRYPOINT ["/entrypoint.sh"]
