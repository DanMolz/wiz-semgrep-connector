FROM ubuntu:latest
LABEL maintainer="Daniel Moloney"
LABEL description="Wiz Semgrep Connector"

RUN apt-get update && apt-get install -y ca-certificates

COPY wiz-semgrep-connector /
COPY docker-entrypoint.sh /

ENTRYPOINT ["sh", "/docker-entrypoint.sh"]