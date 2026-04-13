FROM hugomods/hugo:exts@sha256:dcbc5b53c4e53bb74a7c986caf58a3954395a1e9d8dc9bb492f2c610a7cf6eb0

# Install PostCSS dependencies globally so they survive volume mounts.
# NODE_PATH ensures require() finds globally installed modules from any directory.
RUN npm install -g autoprefixer@10.4.23 postcss@8.5.6 postcss-cli@11.0.1
ENV NODE_PATH=/usr/local/lib/node_modules

# Pre-fetch Hugo modules for faster builds.
WORKDIR /src
COPY go.mod go.sum hugo.yaml ./
RUN hugo mod get

ENV GOBIN=/usr/bin
RUN go install github.com/elastic/crd-ref-docs@v0.3.0