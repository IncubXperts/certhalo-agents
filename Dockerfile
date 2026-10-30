# CertHalo agent (Go) as a small, non-root container.
#   docker run -e CERTHALO_API_KEY=... -v $PWD/targets.txt:/config/targets.txt:ro ghcr.io/incubxperts/certhalo-agent
FROM golang:1.23 AS build
WORKDIR /src
COPY go/ .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /certhalo-agent .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /certhalo-agent /certhalo-agent
ENV CERTHALO_TARGETS=/config/targets.txt
ENTRYPOINT ["/certhalo-agent"]
CMD ["--loop"]
