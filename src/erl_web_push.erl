-module(erl_web_push).

%% API
-export([encrypt/3]).

-ifdef(TEST).

-export([encrypt/6]).

-endif.

-define(CEKINFO, <<"Content-Encoding: aes128gcm\0">>).
-define(NONCEINFO, <<"Content-Encoding: nonce\0">>).

%%==============================================================================================
%% API
%%==============================================================================================
%% TODO: Add a bunch of checks and error types
%% TODO: Write docs
%% TODO: Write tests

-spec encrypt(Message, ClientPubKey, ClientAuthToken) -> {ok, Result} | {error, Error} when
    Message :: binary(),
    ClientPubKey :: binary(),
    ClientAuthToken :: binary(),
    Result :: {Encrypted :: binary(), Salt :: binary(), ServerPubKey :: binary()},
    Error :: todo.
encrypt(Message, ClientPubKey, ClientAuthToken) ->
  Salt = crypto:strong_rand_bytes(16),
  {ServerPubKey, ServerPrivKey} = crypto:generate_key(ecdh, prime256v1),
  encrypt(Message, ClientPubKey, ClientAuthToken, Salt, ServerPubKey, ServerPrivKey).

-spec encrypt( Message
             , ClientPubKey
             , ClientAuthToken
             , Salt
             , ServerPubKey
             , ServerPrivKey
             ) -> {ok, Result} | {error, Error} when
    Message :: binary(),
    ClientPubKey :: binary(),
    ClientAuthToken :: binary(),
    Salt :: binary(),
    ServerPubKey :: binary(),
    ServerPrivKey :: binary(),
    Result :: {Encrypted :: binary(), Salt :: binary(), ServerPubKey :: binary()},
    Error :: todo.
encrypt(Message, ClientPubKey0, ClientAuthToken0, Salt, ServerPubKey, ServerPrivKey) ->
  ClientPubKey = base64_url_decode(ClientPubKey0),
  ClientAuthToken = base64_url_decode(ClientAuthToken0),
  SharedSecret = crypto:compute_key(ecdh, ClientPubKey, ServerPrivKey, prime256v1),
  PseudoRandomKey = hkdf( ClientAuthToken
                        , SharedSecret
                        , <<"WebPush: info", 0, ClientPubKey/binary, ServerPubKey/binary>>
                        , 32
                        ),
  ContentEncryptionKey = hkdf(Salt, PseudoRandomKey, ?CEKINFO, 16),
  Nonce = hkdf(Salt, PseudoRandomKey, ?NONCEINFO, 12),
  {ok, {encrypt_payload(Message, ContentEncryptionKey, Nonce), Salt, ServerPubKey}}.

%%==============================================================================================
%% Internal functions
%%==============================================================================================

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

%% Local variables:
%% mode: erlang
%% erlang-indent-level: 2
%% indent-tabs-mode: nil
%% fill-column: 96
%% coding: utf-8
%% End:
