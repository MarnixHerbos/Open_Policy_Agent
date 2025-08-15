package barmanagement
import future.keywords

default allow := false

iss_base := "https://dev-roqzkvkybxdtnap1.us.auth0.com"
aud := "bar-auth0-api"

bearer_token := input.accessToken

jwks_url := sprintf("%s/.well-known/jwks.json", [iss_base])

jwks_resp := jwks_request(jwks_url)
jwks := jwks_resp.body

# Verify signature as a boolean value (select key by kid)
header_kid := h.kid if { [h, _, _] := io.jwt.decode(bearer_token) }

signing_key := key if {
    jwks
    header_kid
    some i
    key := jwks.keys[i]
    key.kid == header_kid
}

default valid_token := false

# Try verify with JWK
valid_token := true if {
    bearer_token
    signing_key
    io.jwt.verify_rs256(bearer_token, signing_key)
}

# Fallback: verify with first x5c certificate (PEM-wrapped)
valid_token := true if {
    bearer_token
    signing_key
    signing_key.x5c
    count(signing_key.x5c) > 0
    pem := x5c_to_pem(signing_key.x5c[0])
    io.jwt.verify_rs256(bearer_token, pem)
}

# Helper: convert base64 DER x5c to PEM
x5c_to_pem(c) := pem if {
    pem := sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n", [c])
}

iss_ok if {
    [_, payload, _] := io.jwt.decode(bearer_token)
    payload.iss == iss_base
} else if {
    [_, payload, _] := io.jwt.decode(bearer_token)
    payload.iss == sprintf("%s/", [iss_base])
}

claims := payload if {
    valid_token
    [_, payload, _] := io.jwt.decode(bearer_token)
    iss_ok
    aud_ok(payload.aud)
}

aud_ok(a) if {        # aud can be array or string
    is_array(a)
    a[_] == aud
}
aud_ok(a) if {
    is_string(a)
    a == aud
}

allow if {
    input.request.path == "/api/bar"
    input.request.method == "POST"
    input.request.body.DrinkName == "Fristi"
    "customer" in claims.role
}
allow if {
    input.request.path == "/api/bar"
    input.request.method == "POST"
    input.request.body.DrinkName == "Beer"
    "customer" in claims.role
    to_number(claims.age) >= 16
}
allow if {
    input.request.path == "/api/managebar"
    input.request.method == "POST"
    "bartender" in claims.role
}

jwks_request(url) := http.send({
    "url": url,
    "method": "GET",
    "force_cache": true,
    "force_cache_duration_seconds": 300
})


debug_valid := valid_token
debug_claims := claims
debug_input := input
debug_jwks_url := jwks_url
debug_header_kid := header_kid
debug_jwks_kids := {k.kid | k := jwks.keys[_]}
debug_selected_key_kid := signing_key.kid
debug_signing_has_x5c := count(signing_key.x5c) if { signing_key.x5c }