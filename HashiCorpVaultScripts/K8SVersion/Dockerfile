FROM hashicorp/vault

USER root
RUN apk update && apk add --no-cache jq kubectl

COPY init.sh /opt/init.sh
COPY unseal.sh /opt/unseal.sh
RUN chmod +x /opt/init.sh
RUN chmod +x /opt/unseal.sh

ENTRYPOINT ["/bin/sh"]