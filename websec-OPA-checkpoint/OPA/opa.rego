package barmanagement #namespace
import future.keywords
default allow := false #Op true wordt alles toegelaten voor iedereen. Customers kunnen dan ook barmanagement doen.

iss := "https://dev-roqzkvkybxdtnap1.us.auth0.com"
aud := "bar-auth0-api"

allow if {
    input.request.path == "/api/bar"
    input.request.method == "POST"
    input.request.body.DrinkName == "Fristi"
    some r
    r = input.request.claims.role
    r == "customer"

}

allow if {
    input.request.path == "/api/bar"
    input.request.method == "POST"
    input.request.body.DrinkName == "Beer"
    input.request.claims.age >= 16
    some r
    r = input.request.claims.role
    r == "customer"
}

allow if {
    input.request.path == "/api/managebar"
    input.request.method == "POST"

    some r
    r = input.request.claims.role
    r == "bartender"
}

claims := payload if {
    jwks := jwks_request(concat("", [iss, "/.well-known/jwks.js"]))
    constraints := {
        "cert": jwks,
        "iss":concat("", [iss, "/"]),
        "aud": aud
    }
    [_,_,payload] := io.jwt.decode_verify(bearer_token, constraints)
}

jwks_request(url) := http.send({
    "url": url,
    "method": "GET",
    "force_cache": true,
    "force_cache_duration_seconds": 60
})

bearer_token := b if {
    a := input.accessToken
    startswith(a, "Bearer ")
    b := substring(a, count("Bearer "), -1)
}
