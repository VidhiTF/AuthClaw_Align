FROM openpolicyagent/opa:latest

WORKDIR /policies
COPY authclaw.rego /policies/authclaw.rego

EXPOSE 8181

USER 65534

CMD ["run", "--server", "--addr=0.0.0.0:8181", "/policies"]
