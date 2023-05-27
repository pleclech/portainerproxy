FROM --platform=${BUILDPLATFORM} scratch
ARG OS
ARG ARCH

COPY  ./build/portproxy-${OS}-${ARCH} /portproxy

ENTRYPOINT ["/portproxy"]
