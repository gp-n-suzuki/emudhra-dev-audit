# Maintainer-only compatibility test. Wine is not a Windows OS validation.
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends wine64 unzip \
    && rm -rf /var/lib/apt/lists/*
ENV WINEDEBUG=-all WINEPREFIX=/tmp/wine HOME=/tmp LANG=C.UTF-8
USER 65534:65534
ENTRYPOINT ["/bin/bash"]
