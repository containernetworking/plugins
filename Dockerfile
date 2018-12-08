FROM golang:1.11.2 as build

WORKDIR /go/src/app
COPY . .
RUN ./build_linux.sh

FROM busybox
COPY --from=build /go/src/app/bin /opt/cni/bin
WORKDIR /opt/cni/bin

