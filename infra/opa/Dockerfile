FROM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS builder

ARG OPA_VERSION=v1.18.2
RUN CGO_ENABLED=0 go install github.com/open-policy-agent/opa@${OPA_VERSION}

FROM scratch

WORKDIR /policies
COPY --from=builder /go/bin/opa /opa
COPY authclaw.rego /policies/authclaw.rego

EXPOSE 8181

USER 65534

ENTRYPOINT ["/opa"]
CMD ["run", "--server", "--addr=0.0.0.0:8181", "/policies"]
