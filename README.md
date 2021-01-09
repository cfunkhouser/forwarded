# `forwarded`

This library is a set of simple tools for working with HTTP proxy headers.
Intended to be used in HTTP server middleware. By default, the package-level
functions look for RFC 7239 `Forwarded` headers, and then for
`X-Forwarded-{For,By,Host,Proto}` headers. If both exist, the first is trusted.

## Usage

You can use the package-level functions directly as a convenience. They use the
`DefaultStrategy`, as described above.

```go
func ServeHTTP(w http.ResponseWriter, r *http.Request) {
    log.Printf("Original requester: %v", forwarded.For(r.Header))
    log.Printf("Handled by: %v", forwarded.By(r.Header))
    log.Printf("Original protocol: %v", forwarded.Proto(r.Header))
    log.Printf("Original requested host: %v", forwarded.Host(r.Header))
}
```

## Middleware

There is a convenience middleware provided which replaces the `RemoteAddr` field
with the value returned by `For` for the provided strategy.

```go
func doTheThing(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "%v asked me to do the thing.", r.RemoteAddr)
}

func main() {
    mux := http.NewServeMux()

    wrapped := forwarded.ToRemoteAddr(doTheThing, forwarded.DefaultStrategy())

    mux.Handle("/", wrapped)
    log.Fatal(http.ListenAndServe(":3000", mux))
}
```

## Contributing and Development

Contributions welcome. Please submit any feature requests in the form of a pull
request.

### To Do

- Support for RFC 7230 `Via` header.

## References

1. https://tools.ietf.org/html/rfc7239 - RFC describing `Forwarded` headed
2. https://developer.mozilla.org/en-US/docs/Web/HTTP/Proxy_servers_and_tunneling
