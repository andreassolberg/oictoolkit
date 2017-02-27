
An updated verson of the example:

MS0 eduGAIN signs a MS about Feide:

```
{
    'iss': 'https://edugain.org/',
    'aud': 'https://feide.no/',
    'signing_keys': {
        '': 'the public keys of eduGAIN'
    },
    'id_token_signing_alg_values_supported': ['RS256', 'RS512'],
    'claims': ['sub', 'name', 'email', 'picture']
}
```

MS1 Feide signs a MS about UNINETT:

```
{
    'iss': 'https://feide.no/',
    'aud': 'https://uninett.no/',
    'signing_keys': {
        '': 'the public keys of UNINETT'
    }
}
```

MS2 UNINETT signs MS about the client Foodle

```
{
    'iss': 'https://feide.no/',
    'aud': 'https://foodl.org/',
    'sub': 'https://foodl.org/',
    "application_type": "web",
    "redirect_uris": [
        "https://foodl.org/callback"
    ],
    "jwks_uri_signed": "https://foodl.org/jwks",
    'signing_keys': {
        '': 'the public keys of Feide'
    }
}
```


## Questions:

* Re-registration of timed out client registrations. Will be short-lived because of section 7.
