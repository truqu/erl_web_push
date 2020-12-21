%% @doc {@module} allows preparing payloads for web push.
-module(erl_web_push).

%% API
-export([encrypt/3, request/1, request/2, vapid_request/2, vapid_request/3]).

-ifdef(TEST).

-export([encrypt/6]).

-endif.

-define(CEKINFO, <<"Content-Encoding: aes128gcm\0">>).
-define(NONCEINFO, <<"Content-Encoding: nonce\0">>).

%% @doc Encrypts the `Message' according to the procedure as described in rfc8291 using the
%% provided `ClientPubKey' (base64 encoded, url-safe or not) and `ClientAuthToken' (similar).
%%
%% This generates a fresh, random keypair for the server side, with the public key being
%% returned by this call, together with the random salt and the encrypted result. All three of
%% these are returned as raw binaries.

-spec encrypt(Message, ClientPubKey, ClientAuthToken) -> {ok, Result} | {error, Error} when
    Message :: binary(),
    ClientPubKey :: binary(),
    ClientAuthToken :: binary(),
    Result :: {Encrypted :: binary(), Salt :: binary(), ServerPubKey :: binary()},
    Error :: message_too_long | invalid_pubkey_or_token.
encrypt(Message, _, _) when byte_size(Message) > 4078 -> {error, message_too_long};
encrypt(Message, ClientPubKey0, ClientAuthToken0) ->
  ClientPubKey = base64_url_decode(ClientPubKey0),
  ClientAuthToken = base64_url_decode(ClientAuthToken0),
  case {byte_size(ClientPubKey), byte_size(ClientAuthToken)} of
    {65, 16} ->
      Salt = crypto:strong_rand_bytes(16),
      {ServerPubKey, ServerPrivKey} = crypto:generate_key(ecdh, prime256v1),
      {ok, encrypt(Message, ClientPubKey, ClientAuthToken, Salt, ServerPubKey, ServerPrivKey)};
    {_, _} -> {error, invalid_pubkey_or_token}
  end.

-spec request(Payload) -> Result when
    Payload :: {Encrypted :: binary(), Salt :: binary(), ServerPubKey :: binary()},
    Result :: {Headers, Body},
    Headers :: [{binary(), binary()}],
    Body :: binary().
request(Payload) -> request(Payload, 12 * 3600).

-spec request(Payload, TTL) -> Result when
    Payload :: {Encrypted :: binary(), Salt :: binary(), ServerPubKey :: binary()},
    TTL :: non_neg_integer(),
    Result :: {Headers, Body},
    Headers :: [{binary(), binary()}],
    Body :: binary().
request({Encrypted, Salt, PubKey}, TTL) when
    byte_size(Salt) =:= 16,
    byte_size(PubKey) =:= 65,
    TTL >= 0 ->
  Now = erlang:system_time(second),
  Expire = integer_to_binary(Now + TTL),
  Headers = [ {<<"content-type">>, <<"application/octet-stream">>}
            , {<<"content-encoding">>, <<"aesgcm">>}
            , {<<"encryption">>, <<"salt=", (base64_url_encode(Salt))/binary>>}
            , {<<"crypto-key">>, <<"dh=", (base64_url_encode(PubKey))/binary>>}
            , {<<"ttl">>, Expire}
            ],
  {Headers, base64_url_encode(Encrypted)}.

-spec vapid_request(Target, Payload) -> Result when
    Target :: binary(),
    Payload :: {Encrypted :: binary(), Salt :: binary(), ServerPubKey :: binary()},
    Result :: {Headers, Body},
    Headers :: [{binary(), binary()}],
    Body :: binary().
vapid_request(Target, Payload) -> vapid_request(Target, Payload, 12 * 3600).

%% KeyInfo, json encoder: application config!
%% Need to throw appropriate errors, too!

-spec vapid_request(Target, Payload, TTL) -> Result when
    Target :: binary(),
    Payload :: {Encrypted :: binary(), Salt :: binary(), ServerPubKey :: binary()},
    TTL :: non_neg_integer(),
    Result :: {Headers, Body},
    Headers :: [{binary(), binary()}],
    Body :: binary().
vapid_request(Target, Payload, TTL) ->
  Now = erlang:system_time(second),
  Expire = integer_to_binary(Now + TTL),
  {Headers, Body} = request(Payload, TTL),
  {VapidPubKey, VapidPrivKey} = vapid_keys(),
  JWTHeader = <<"{\"typ\": \"JWT\",\"alg\": \"ES256\"}">>,
  JWTPayload = json_encode(#{ <<"aud">> => extract_audience(Target)
                            , <<"exp">> => Expire
                            , <<"sub">> => vapid_contact()
                            }),
  ToSign =
    <<(base64_url_encode(JWTHeader))/binary, ".", (base64_url_encode(JWTPayload))/binary>>,
  Signature = crypto:sign(ecdsa, sha256, ToSign, VapidPrivKey),
  JWT = <<ToSign/binary, ".", (base64_url_encode(Signature))/binary>>,
  {[{<<"crypto-key">>, CKHeader}], Rest} = proplists:split(<<"crypto-key">>, Headers),
  { [ { <<"crypto-key">>
      , <<CKHeader/binary, ",p256ecdsa=", (base64_url_encode(VapidPubKey))/binary>>
      }
    , {<<"authorization">>, <<"WebPush ", JWT/binary>>} | Rest
    ]
  , Body
  }.

-spec vapid_keys() -> {PubKey :: binary(), PrivKey :: binary()}.
vapid_keys() -> {<<>>, <<>>}.

-spec extract_audience(URL :: binary()) -> binary().
extract_audience(X) -> X.

-spec vapid_contact() -> binary().
vapid_contact() -> <<>>.

-spec json_encode(map()) -> binary().
json_encode(_) -> <<>>.

%% @hidden
-spec encrypt( Message
             , ClientPubKey
             , ClientAuthToken
             , Salt
             , ServerPubKey
             , ServerPrivKey
             ) -> Result when
    Message :: binary(),
    ClientPubKey :: binary(),
    ClientAuthToken :: binary(),
    Salt :: binary(),
    ServerPubKey :: binary(),
    ServerPrivKey :: binary(),
    Result :: {Encrypted :: binary(), Salt :: binary(), ServerPubKey :: binary()}.
encrypt(Message, ClientPubKey, ClientAuthToken, Salt, ServerPubKey, ServerPrivKey) ->
  SharedSecret = crypto:compute_key(ecdh, ClientPubKey, ServerPrivKey, prime256v1),
  PseudoRandomKey = hkdf( ClientAuthToken
                        , SharedSecret
                        , <<"WebPush: info", 0, ClientPubKey/binary, ServerPubKey/binary>>
                        , 32
                        ),
  ContentEncryptionKey = hkdf(Salt, PseudoRandomKey, ?CEKINFO, 16),
  Nonce = hkdf(Salt, PseudoRandomKey, ?NONCEINFO, 12),
  {encrypt_payload(Message, ContentEncryptionKey, Nonce), Salt, ServerPubKey}.

-spec hkdf(binary(), binary(), binary(), pos_integer()) -> binary().
hkdf(Salt, InputKeyMaterial, Info, Length) ->
  PseudoRandomKey = crypto:mac(hmac, sha256, Salt, InputKeyMaterial),
  crypto:macN(hmac, sha256, PseudoRandomKey, <<Info/binary, 1>>, Length).

encrypt_payload(Message, CEK, Nonce) ->
  {Text, Tag} =
    crypto:crypto_one_time_aead(aes_128_gcm, CEK, Nonce, <<Message/binary, 2>>, [], true),
  <<Text/binary, Tag/binary>>.

-spec base64_url_decode(binary()) -> binary().
base64_url_decode(V) ->
  base64:decode(pad_base64(binary:replace( binary:replace(V, <<"-">>, <<"+">>, [global])
                                         , <<"_">>
                                         , <<"/">>
                                         , [global]
                                         ))).

-spec pad_base64(binary()) -> binary().
pad_base64(V) ->
  case size(V) rem 4 of
    0 -> V;
    1 -> <<V/binary, "===">>;
    2 -> <<V/binary, "==">>;
    3 -> <<V/binary, "=">>
  end.

-spec base64_url_encode(binary()) -> binary().
base64_url_encode(V) ->
  binary:replace( binary:replace( binary:replace(base64:encode(V), <<"+">>, <<"-">>, [global])
                                , <<"/">>
                                , <<"_">>
                                , [global]
                                )
                , <<"=">>
                , <<>>
                , [global]
                ).

%% Local variables:
%% mode: erlang
%% erlang-indent-level: 2
%% indent-tabs-mode: nil
%% fill-column: 96
%% coding: utf-8
%% End:
