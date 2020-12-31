%% @doc {@module} allows preparing payloads for web push.
-module(erl_web_push).

%% Encryption
-export([encrypt/3]).

%% Requests
-export([request/1, request/2]).

%% Vapid
-export([vapid_request/2, vapid_request/3, generate_vapid_keys/0, vapid_public_key/0]).

-ifdef(TEST).

-export([encrypt/6]).

-endif.

-type encryption_result() ::
        {Encrypted :: binary(), Salt :: binary(), ServerPubKey :: binary()}.
-type encryption_error() :: message_too_long | invalid_pubkey_or_token.

-export_type([encryption_result/0, encryption_error/0]).

-define(CEKINFO, <<"Content-Encoding: aes128gcm\0">>).
-define(NONCEINFO, <<"Content-Encoding: nonce\0">>).
-define(RECORD_LENGTH, 4096).

% See https://www.rfc-editor.org/rfc/rfc3279.html
-define(PRIME256V1_OID, {1, 2, 840, 10045, 3, 1, 7}).

%% @doc Returns the VAPID public key as set in the application env.
%%
%% Exits with a `badmatch' error if no VAPID public key was configured. To generate a keypair
%% which you can add to the application env, see {@link generate_vapid_keys/0}.
%%
%% @throws {error, {badmatch, undefined}}

-spec vapid_public_key() -> binary().
vapid_public_key() ->
  {ok, PubKey} = application:get_env(erl_web_push, vapid_public_key),
  PubKey.

%% @doc Generates a valid VAPID keypair, and returns a proplist for us in the application env.
%%
%% The generated keypair is usable with ECDSA over the P-256 curve, as specified in
%% [https://tools.ietf.org/id/draft-ietf-webpush-vapid-03.html].
%%
%% These keys must be added to the application env, for example through `sys.config', in order
%% to make use of functions like {@link vapid_request/2} and {@link vapid_request/3}.

-spec generate_vapid_keys() -> proplists:proplist().
generate_vapid_keys() ->
  {PubKey, PrivKey} = crypto:generate_key(ecdh, prime256v1),
  [ {vapid_public_key, base64_url_encode(PubKey)}
  , {vapid_private_key, base64_url_encode(PrivKey)}
  ].

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
    Result :: encryption_result(),
    Error :: encryption_error().
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

%% @equiv request(Payload, 12 * 3600)
-spec request(Payload) -> Result when
    Payload :: encryption_result(),
    Result :: {Headers, Body},
    Headers :: [{binary(), binary()}],
    Body :: binary().
request(Payload) -> request(Payload, 12 * 3600).

%% @doc Prepares headers and body for an HTTP request, given the result of {@link encrypt/3} and
%% a TTL expressed in seconds.
-spec request(Payload, TTL) -> Result when
    Payload :: encryption_result(),
    TTL :: non_neg_integer(),
    Result :: {Headers, Body},
    Headers :: [{binary(), binary()}],
    Body :: binary().
request({Encrypted, Salt, PubKey}, TTL) when
    byte_size(Salt) =:= 16,
    byte_size(PubKey) =:= 65,
    TTL >= 0 ->
  Header = << Salt/binary
            , ?RECORD_LENGTH:32/unsigned-big-integer
            , (byte_size(PubKey)):8/unsigned-big-integer
            , PubKey/binary
           >>,
  Headers = [{<<"content-encoding">>, <<"aes128gcm">>}, {<<"ttl">>, integer_to_binary(TTL)}],
  {Headers, <<Header/binary, Encrypted/binary>>}.

%% @equiv vapid_request(Target, Payload, 12*3600)
-spec vapid_request(Target, Payload) -> Result when
    Target :: binary(),
    Payload :: encryption_result(),
    Result :: {Headers, Body},
    Headers :: [{binary(), binary()}],
    Body :: binary().
vapid_request(Target, Payload) -> vapid_request(Target, Payload, 12 * 3600).

%% @doc Prepares headers and body for an HTTP request leveraging VAPID.
%%
%% @see request/2
%% @see generate_vapid_keypair/2

-spec vapid_request(Target, Payload, TTL) -> Result when
    Target :: binary(),
    Payload :: encryption_result(),
    TTL :: non_neg_integer(),
    Result :: {Headers, Body},
    Headers :: [{binary(), binary()}],
    Body :: binary().
vapid_request(Target, Payload, TTL) ->
  Now = erlang:system_time(second),
  Expire = Now + (12 * 3600),
  {Headers, Body} = request(Payload, TTL),
  {VapidPubKey, VapidPrivKey} = vapid_keys(),
  JWT = sign_jwt( #{<<"typ">> => <<"JWT">>, <<"alg">> => <<"ES256">>}
                , #{ <<"aud">> => extract_audience(Target)
                   , <<"exp">> => Expire
                   , <<"sub">> => vapid_contact()
                   }
                , VapidPrivKey
                ),
  { [{<<"authorization">>, <<"vapid t=", JWT/binary, ", k=", VapidPubKey/binary>>} | Headers]
  , Body
  }.

%%==============================================================================================
%% Internal functions
%%==============================================================================================

-spec sign_jwt(Header, Payload, PrivKey) -> Signed when
    Header :: map(),
    Payload :: map(),
    PrivKey :: binary(),
    Signed :: binary().
sign_jwt(Header, Payload, PrivKey) ->
  ToSign = << (base64_url_encode(json_encode(Header)))/binary
            , "."
            , (base64_url_encode(json_encode(Payload)))/binary
           >>,
  Asn1Sig = crypto:sign(ecdsa, sha256, ToSign, [base64_url_decode(PrivKey), prime256v1]),
  {'ECDSA-Sig-Value', R, S} = public_key:der_decode('ECDSA-Sig-Value', Asn1Sig),
  Signature = base64_url_encode(<<R:256, S:256>>),
  <<ToSign/binary, ".", Signature/binary>>.

-spec vapid_keys() -> {PubKey :: binary(), PrivKey :: binary()}.
vapid_keys() ->
  {ok, PubKey} = application:get_env(erl_web_push, vapid_public_key),
  {ok, PrivKey} = application:get_env(erl_web_push, vapid_private_key),
  {PubKey, PrivKey}.

-spec extract_audience(URL :: binary()) -> binary().
extract_audience(X) ->
  Top = uri_string:resolve(<<"/">>, X),
  binary:part(Top, {0, byte_size(Top) - 1}).

-spec vapid_contact() -> binary().
vapid_contact() ->
  {ok, Contact} = application:get_env(erl_web_push, vapid_contact),
  Contact.

-spec json_encode(map()) -> binary().
json_encode(Val) ->
  {M, F, A} = case application:get_env(erl_web_push, json_encode) of
                {ok, {Modul, Fun}} -> {Modul, Fun, [Val]};
                {ok, {Modul, Fun, Extra}} -> {Modul, Fun, [Val | Extra]}
              end,
  apply(M, F, A).

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
    Result :: encryption_result().
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
