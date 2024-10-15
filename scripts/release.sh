#!/usr/bin/env sh
set -xe

SRC_DIR="${SRC_DIR:-$PWD}"
DOCKER="${DOCKER:-docker}"

GO_IMAGE="${GO_IMAGE:-golang}"
GO_VERSION="${GO_VERSION:-1.22-alpine}"
GOLANG="${GO_IMAGE}:${GO_VERSION}"

_defaultTag=$(git describe --tags --dirty)
TAG=${TAG:-$_defaultTag}
RELEASE_DIR=release-${TAG}

DOCKER_RUN_ARGS=${DOCKER_RUN_ARGS:-'-ti'}

CGO_ENABLED="${CGO_ENABLED:-0}"
EXTLDFLAGS_LINUX=""
if [ "${CGO_ENABLED}" == "0" ]; then
  EXTLDFLAGS_LINUX="-extldflags -static"
fi

GOARCH_LIST="${GOARCH_LIST:-amd64 arm arm64 ppc64le s390x mips64le riscv64}"

BUILDFLAGS_LINUX="-ldflags '${EXTLDFLAGS_LINUX} -X github.com/containernetworking/plugins/pkg/utils/buildversion.BuildVersion=${TAG}'"
BUILDFLAGS_WINDOWS="-ldflags '-extldflags -static -X github.com/containernetworking/plugins/pkg/utils/buildversion.BuildVersion=${TAG}'"

OUTPUT_DIR=bin

# Always clean first
rm -Rf ${SRC_DIR}/${RELEASE_DIR}
mkdir -p ${SRC_DIR}/${RELEASE_DIR}
mkdir -p ${OUTPUT_DIR}

$DOCKER run ${DOCKER_RUN_ARGS} -v ${SRC_DIR}:/go/src/github.com/containernetworking/plugins:z --rm "${GOLANG}" \
/bin/sh -xe -c "\
    for cmd in bash tar; do
      command -v apk && apk --no-cache add \$cmd
      command -v \$cmd || (echo \$cmd not found && exit 1);
    done

    cd /go/src/github.com/containernetworking/plugins; umask 0022;

    for arch in ${GOARCH_LIST}; do \
        rm -f ${OUTPUT_DIR}/*; \
        CGO_ENABLED=${CGO_ENABLED} GOARCH=\$arch ./build_linux.sh ${BUILDFLAGS_LINUX}; \
        for format in tgz; do \
            FILENAME=cni-plugins-linux-\$arch-${TAG}.\$format; \
            FILEPATH=${RELEASE_DIR}/\$FILENAME; \
            tar -C ${OUTPUT_DIR} --owner=0 --group=0 -caf \$FILEPATH .; \
        done; \
    done;

    rm -rf ${OUTPUT_DIR}/*; \
    CGO_ENABLED=0 GOARCH=amd64 ./build_windows.sh ${BUILDFLAGS_WINDOWS}; \
    for format in tgz; do \
        FILENAME=cni-plugins-windows-amd64-${TAG}.\$format; \
        FILEPATH=${RELEASE_DIR}/\$FILENAME; \
        tar -C ${OUTPUT_DIR} --owner=0 --group=0 -caf \$FILEPATH .; \
    done;


    cd ${RELEASE_DIR};
      for f in *.tgz; do sha1sum \$f > \$f.sha1; done;
      for f in *.tgz; do sha256sum \$f > \$f.sha256; done;
      for f in *.tgz; do sha512sum \$f > \$f.sha512; done;
    cd ..
    chown -R ${UID} ${OUTPUT_DIR} ${RELEASE_DIR}"
