FROM --platform=$BUILDPLATFORM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS builder

ARG OPA_VERSION=v1.18.2
ARG BUILDOS
ARG BUILDARCH
ARG TARGETOS
ARG TARGETARCH
ARG TARGETPLATFORM
RUN test "$TARGETPLATFORM" = "$TARGETOS/$TARGETARCH" \
    && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go install github.com/open-policy-agent/opa@${OPA_VERSION} \
    && mkdir -p /out \
    && if [ "$BUILDOS/$BUILDARCH" = "$TARGETOS/$TARGETARCH" ]; then cp /go/bin/opa /out/opa; \
       else cp "/go/bin/${TARGETOS}_${TARGETARCH}/opa" /out/opa; fi
WORKDIR /src
COPY healthcheck.go .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/healthcheck ./healthcheck.go

FROM scratch

WORKDIR /policies
COPY --from=builder /out/opa /opa
COPY --from=builder /out/healthcheck /healthcheck
COPY authclaw.rego /policies/authclaw.rego

EXPOSE 8181

USER 65534

ENTRYPOINT ["/opa"]
CMD ["run", "--server", "--addr=0.0.0.0:8181", "/policies"]
