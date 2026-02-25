# -------- BUILD STAGE --------
FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake ninja-build build-essential pkg-config \
    libssl-dev \
    libpq-dev \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
 && cmake --build build


# -------- RUNTIME STAGE --------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    libssl3 \
    libpq5 \
    postgresql-client \
    openssl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=build /app/build /app/build
COPY --from=build /app/src /app/src

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 3434

ENTRYPOINT ["/entrypoint.sh"]