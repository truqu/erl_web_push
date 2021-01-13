# erl\_web\_push

Web push library in Erlang. Provides helpers for encrypting (RFC-8188) messages,
preparing requests (RFC-8291) and opting in to VAPID (RFC-8292).

## Installation

`erl_web_push` is published on [hex.pm](https://hex.pm/packages/erl_web_push).

## Configuration

In order to leverage VAPID, certain configuration keys have to be set:

- `vapid_public_key`: A base64 (optionally url-safe) encoded P256 public key.

  The public key is communicated through the `k` parameter of the
  `authorization` header, returned by `vapid_request/{2,3}`

- `vapid_private_key`: Corresponding base64 (optionally url-safe) encoded P256
  private key.

  Used to sign the JWT token, communicated through the `t` parameter of the
  `authorization` header, returned by `vapid_request/{2,3}`

- `vapid_contact`: Either a `mailto:` (email) or `https:` URI where push
  providers can contact you

- `json_encode`: An `{M, F}` or `{M, F, A}` tuple describing a function to
  encode json.

  When `{M, F}` is provided, `erl_web_push` will call `M:F(Map)` (where `Map` is
  some JSON to encode). When `{M, F, A}` is provided, `A` is expected to be a
  list of arguments, which will follow `Map`. In other words, expect evaluation
  equivalent to `apply(M, F, [Map | A])`.

These keys are expected to be found as configuration parameters in the
`erl_web_application`. Accordingly, add a section like so to your `sys.config`
or otherwise ensure these configuration parameters can be retrieved.

```erlang
[ ...
, {erl_web_push, [ {vapid_public_key, <<...>>}
                 , {vapid_private_key, <<...>>}
                 , ...
                 ]}
].
```

Calling `erl_web_push:generate_vapid_keys()` will generate a keypair, returning
it as a formatted list of tuples which can be used in `sys.config`.
