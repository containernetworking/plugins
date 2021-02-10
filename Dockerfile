# In this container we test the install script
FROM busybox as test

ADD docker-installer/install_cni_plugins.sh /script/install_cni_plugins.sh
ADD docker-installer/test_install_cni_plugins.sh /script/test_install_cni_plugins.sh
WORKDIR /script
RUN /script/test_install_cni_plugins.sh

# In this container we build the plug-ins
FROM golang:1.15 as build

ENV BRANCH_OR_TAG=master

WORKDIR /go/src/app
ADD . .
RUN ./build_linux.sh

# This is the final, minimal container
FROM busybox
COPY --from=build /go/src/app/bin /opt/cni/bin
VOLUME /host/opt/cni/bin
ADD docker-installer/install_cni_plugins.sh /script/install_cni_plugins.sh
CMD ["/script/install_cni_plugins.sh","/opt/cni/bin","/host/opt/cni/bin"]
