FROM busybox as test

ADD docker-installer/install_cni_plugins.sh /script/install_cni_plugins.sh
ADD docker-installer/test_install_cni_plugins.sh /script/test_install_cni_plugins.sh
WORKDIR /script
RUN /script/test_install_cni_plugins.sh

FROM busybox as build
ARG TAG
# Get buildx automatic platform vars: https://docs.docker.com/engine/reference/builder/#automatic-platform-args-in-the-global-scope
ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG BUILDPLATFORM
ARG BUILDOS
ARG BUILDARCH
ARG BUILDVARIANT
RUN echo TARGETPLATFORM=$TARGETPLATFORM
RUN echo TARGETOS=$TARGETOS
RUN echo TARGETARCH=$TARGETARCH
RUN echo TARGETVARIANT=$TARGETVARIANT
RUN echo BUILDPLATFORM=$BUILDPLATFORM
RUN echo BUILDOS=$BUILDOS
RUN echo BUILDARCH=$BUILDARCH
RUN echo BUILDVARIANT=$BUILDVARIANT
# Use buildx automatic platform vars
COPY release-$TAG/cni-plugins-$TARGETOS-$TARGETARCH-$TAG.tgz cni-plugins-$TARGETOS-$TARGETARCH-$TAG.tgz
COPY release-$TAG/cni-plugins-$TARGETOS-$TARGETARCH-$TAG.tgz.sha512 cni-plugins-$TARGETOS-$TARGETARCH-$TAG.tgz.sha512
RUN set -eux; \
    sha512sum -c cni-plugins-$TARGETOS-$TARGETARCH-$TAG.tgz.sha512; \
    mkdir -p /opt/cni/bin; \
    tar -xvf cni-plugins-$TARGETOS-$TARGETARCH-$TAG.tgz -C /opt/cni/bin;

# This is the final, minimal container
FROM busybox as final
COPY docker-installer/install_cni_plugins.sh /script/install_cni_plugins.sh
COPY --from=build /opt/cni/bin /opt/cni/bin
ENV FORCE=
WORKDIR /opt/cni/bin
VOLUME /host/opt/cni/bin
CMD ["/script/install_cni_plugins.sh","/opt/cni/bin","/host/opt/cni/bin"]
