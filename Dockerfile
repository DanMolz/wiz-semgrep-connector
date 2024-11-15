FROM ubuntu:latest
LABEL maintainer="Daniel Moloney"
LABEL description="Wiz Semgrep Connector"

COPY wiz-semgrep-connector /
COPY docker-entrypoint.sh /

ENTRYPOINT ["sh", "/docker-entrypoint.sh"]