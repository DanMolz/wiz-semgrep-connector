FROM ubuntu:latest
LABEL maintainer="Daniel Moloney"
LABEL description="Wiz Semgrep Connector"

RUN groupadd -g 1001 wizards && \
  useradd -m -u 1001 -g wizards wizard
RUN apt-get update && apt-get install -y ca-certificates

COPY wiz-semgrep-connector /
COPY docker-entrypoint.sh /

USER wizard:wizards

ENTRYPOINT ["sh", "/docker-entrypoint.sh"]