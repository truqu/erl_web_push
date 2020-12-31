-module(erl_web_push_SUITE).

-include_lib("stdlib/include/assert.hrl").

-export([all/0, groups/0]).

%% Tests
-export([ encrypt_correctly_encrypts_known_good_values_1/1
        , encrypt_correctly_encrypts_known_good_values_2/1
        , encrypt_message_too_long_error/1
        , encrypt_invalid_authtoken_error/1
        , encrypt_invalid_pubkey_error/1
        , encrypt_generates_valid_encrypted_result/1
        , request_ttl_defaults_to_12_hours/1
        , request_uses_aes128gcm_encoding/1
        , request_formats_content/1
        , vapid_request_fails_if_pubkey_not_set/1
        , vapid_request_fails_if_privkey_not_set/1
        , vapid_request_fails_if_contact_not_set/1
        , vapid_request_fails_if_json_encode_not_set/1
        , vapid_request_adds_valid_jwt_header/1
        ]).

-spec all() -> [any()].
all() -> [{group, g_all}].

-spec groups() -> any().
groups() ->
  [ {g_all, [parallel], [{group, g_encrypt}, {group, g_request}, {group, g_vapid}]}
  , { g_encrypt
    , [parallel]
    , [ encrypt_correctly_encrypts_known_good_values_1
      , encrypt_correctly_encrypts_known_good_values_2
      , encrypt_message_too_long_error
      , encrypt_invalid_authtoken_error
      , encrypt_invalid_pubkey_error
      , encrypt_generates_valid_encrypted_result
      ]
    }
  , { g_request
    , [parallel]
    , [ request_ttl_defaults_to_12_hours
      , request_uses_aes128gcm_encoding
      , request_formats_content
      ]
    }
  , { g_vapid
    , [ vapid_request_fails_if_pubkey_not_set
      , vapid_request_fails_if_privkey_not_set
      , vapid_request_fails_if_contact_not_set
      , vapid_request_fails_if_json_encode_not_set
      , vapid_request_adds_valid_jwt_header
      ]
    }
  ].

-define( ENCRYPTED_RESULT
       , { <<"encrypted">>
         , list_to_binary(lists:duplicate(16, $a))
         , list_to_binary(lists:duplicate(65, $a))
         }
       ).

%%==============================================================================================
%% Tests
%%==============================================================================================

-spec encrypt_correctly_encrypts_known_good_values_1(any()) -> any().
encrypt_correctly_encrypts_known_good_values_1(_) ->
  %% Values from https://tests.peter.sh/push-encryption-verifier/
  Salt = base64:decode(<<"4CQCKEyyOT/LysC17rsMXQ==">>),
  ServerPub = base64:decode(<< "BG3OGHrl3YJ5PHpl0GSqtAAlUPnx1LvwQvFMIc68vhJU6"
                               "nIkRzPEqtCduQz8wQj0r71NVPzr7ZRk2f+fhsQ5pK8="
                            >>),
  ServerPriv = base64:decode(<<"Dt1CLgQlkiaA+tmCkATyKZeoF1+Gtw1+gdEP6pOCqj4=">>),
  Message = <<"Hello, world!">>,
  ClientPubKey = base64:decode(<< "BOLcHOg4ajSHR6BjbSBeX/6aXjMu1V5RrUYXqyV/Fqt"
                                  "QSd8RzdU1gkMv1DlRPDIUtFK6Nd16Jql0eSzyZh4V2uc="
                               >>),
  ClientAuthToken = base64:decode(<<"r9kcFt8+4Q6MnMjJHqJoSQ==">>),
  {Enc, Salt, ServerPub} =
    erl_web_push:encrypt(Message, ClientPubKey, ClientAuthToken, Salt, ServerPub, ServerPriv),
  ?assertEqual(base64:decode(<<"qbU60BXbSk+PKtJPKD3z9KEs3le4+23LJkC04+2E">>), Enc).

-spec encrypt_correctly_encrypts_known_good_values_2(any()) -> any().
encrypt_correctly_encrypts_known_good_values_2(_) ->
  %% Values from https://tools.ietf.org/html/rfc8291
  Salt = base64:decode(<<"DGv6ra1nlYgDCS1FRnbzlw==">>),
  ServerPub = base64:decode(<< "BP4z9KsN6nGRTbVYI/c7VJSPQTBtkgcy27mlmlMoZIIg"
                               "Dll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8="
                            >>),
  ServerPriv = base64:decode(<<"yfWPiYE+n46HLnH0KqZOF1fJJU3MYrct3AELtAQ+oRw=">>),
  Message = <<"When I grow up, I want to be a watermelon">>,
  ClientPubKey = base64:decode(<< "BCVxsr7N/eNgVRqvHtD0zTZsEc6+VV+JvLexhqUzOR"
                                  "cxaOzi6+AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4="
                               >>),
  ClientAuthToken = base64:decode(<<"BTBZMqHH6r4Tts7J/aSIgg==">>),
  {Enc, Salt, ServerPub} =
    erl_web_push:encrypt(Message, ClientPubKey, ClientAuthToken, Salt, ServerPub, ServerPriv),
  Expected =
    <<"8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI/0LpXMuGvnzQ==">>,
  ?assertEqual(base64:decode(Expected), Enc).

-spec encrypt_message_too_long_error(any()) -> any().
encrypt_message_too_long_error(_) ->
  Message = list_to_binary(lists:duplicate(4079, $a)),
  ClientPubKey = << "BCVxsr7N/eNgVRqvHtD0zTZsEc6+VV+JvLexhqUzOR"
                    "cxaOzi6+AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4="
                 >>,
  ClientAuthToken = <<"BTBZMqHH6r4Tts7J/aSIgg==">>,
  ?assertEqual( {error, message_too_long}
              , erl_web_push:encrypt(Message, ClientPubKey, ClientAuthToken)
              ).

-spec encrypt_invalid_authtoken_error(any()) -> any().
encrypt_invalid_authtoken_error(_) ->
  Message = list_to_binary(lists:duplicate(4078, $a)),
  ClientPubKey = << "BCVxsr7N/eNgVRqvHtD0zTZsEc6+VV+JvLexhqUzOR"
                    "cxaOzi6+AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4="
                 >>,
  ClientAuthToken = base64:encode(lists:duplicate(17, $a)),
  ?assertEqual( {error, invalid_pubkey_or_token}
              , erl_web_push:encrypt(Message, ClientPubKey, ClientAuthToken)
              ).

-spec encrypt_invalid_pubkey_error(any()) -> any().
encrypt_invalid_pubkey_error(_) ->
  Message = list_to_binary(lists:duplicate(4078, $a)),
  ClientPubKey = base64:encode(lists:duplicate(66, $a)),
  ClientAuthToken = <<"BTBZMqHH6r4Tts7J/aSIgg==">>,
  ?assertEqual( {error, invalid_pubkey_or_token}
              , erl_web_push:encrypt(Message, ClientPubKey, ClientAuthToken)
              ).

-spec encrypt_generates_valid_encrypted_result(any()) -> any().
encrypt_generates_valid_encrypted_result(_) ->
  AuthToken = crypto:strong_rand_bytes(16),
  {ClientPubKey, ClientPrivKey} = crypto:generate_key(ecdh, prime256v1),
  Message = <<"this is a random message">>,
  {ok, {Encrypted, Salt, ServerPubKey}} =
    erl_web_push:encrypt(Message, base64:encode(ClientPubKey), base64:encode(AuthToken)),
  SharedSecret = crypto:compute_key(ecdh, ServerPubKey, ClientPrivKey, prime256v1),
  PRKHKDF = crypto:mac(hmac, sha256, AuthToken, SharedSecret),
  PRK = crypto:macN( hmac
                   , sha256
                   , PRKHKDF
                   , <<"WebPush: info", 0, ClientPubKey/binary, ServerPubKey/binary, 1>>
                   , 32
                   ),
  HKDF = crypto:mac(hmac, sha256, Salt, PRK),
  CEK = crypto:macN(hmac, sha256, HKDF, <<"Content-Encoding: aes128gcm", 0, 1>>, 16),
  Nonce = crypto:macN(hmac, sha256, HKDF, <<"Content-Encoding: nonce", 0, 1>>, 12),
  <<CipherText:25/binary, Tag:16/binary>> = Encrypted,
  Result = crypto:crypto_one_time_aead(aes_128_gcm, CEK, Nonce, CipherText, [], Tag, false),
  ?assertMatch(<<Message:24/binary, 2>>, Result).

-spec request_ttl_defaults_to_12_hours(any()) -> any().
request_ttl_defaults_to_12_hours(_) ->
  {Headers, _} = erl_web_push:request(?ENCRYPTED_RESULT),
  ?assertEqual(<<"43200">>, proplists:get_value(<<"ttl">>, Headers)).

-spec request_uses_aes128gcm_encoding(any()) -> any().
request_uses_aes128gcm_encoding(_) ->
  {Headers, _} = erl_web_push:request(?ENCRYPTED_RESULT),
  ?assertEqual(<<"aes128gcm">>, proplists:get_value(<<"content-encoding">>, Headers)).

-spec request_formats_content(any()) -> any().
request_formats_content(_) ->
  Salt = list_to_binary(lists:duplicate(16, $a)),
  PubKey = list_to_binary(lists:duplicate(65, $a)),
  {_, Body} = erl_web_push:request(?ENCRYPTED_RESULT),
  ?assertMatch( << Salt:16/binary
                 , 4096:32/unsigned-big-integer
                 , 65:8/unsigned-big-integer
                 , PubKey:65/binary
                 , "encrypted"
                >>
              , Body
              ).

-spec vapid_request_fails_if_pubkey_not_set(any()) -> any().
vapid_request_fails_if_pubkey_not_set(_) ->
  ?assertError( {badmatch, undefined}
              , erl_web_push:vapid_request(<<"https://example.org/path">>, ?ENCRYPTED_RESULT)
              ).

-spec vapid_request_fails_if_privkey_not_set(any()) -> any().
vapid_request_fails_if_privkey_not_set(_) ->
  Keys = erl_web_push:generate_vapid_keys(),
  application:set_env( erl_web_push
                     , vapid_public_key
                     , proplists:get_value(vapid_public_key, Keys)
                     ),
  ?assertError( {badmatch, undefined}
              , erl_web_push:vapid_request(<<"https://example.org/path">>, ?ENCRYPTED_RESULT)
              ).

-spec vapid_request_fails_if_contact_not_set(any()) -> any().
vapid_request_fails_if_contact_not_set(_) ->
  Keys = erl_web_push:generate_vapid_keys(),
  application:set_env([{erl_web_push, Keys}]),
  ?assertError( {badmatch, undefined}
              , erl_web_push:vapid_request(<<"https://example.org/path">>, ?ENCRYPTED_RESULT)
              ).

-spec vapid_request_fails_if_json_encode_not_set(any()) -> any().
vapid_request_fails_if_json_encode_not_set(_) ->
  application:set_env([{erl_web_push, [{vapid_contact, <<"mailto:development@truqu.com">>}]}]),
  ?assertError( {case_clause, undefined}
              , erl_web_push:vapid_request(<<"https://example.org/path">>, ?ENCRYPTED_RESULT)
              ).

-spec vapid_request_adds_valid_jwt_header(any()) -> any().
vapid_request_adds_valid_jwt_header(_) ->
  application:set_env([{erl_web_push, [{json_encode, {jsx, encode}}]}]),
  {Headers, _} = erl_web_push:vapid_request(<<"https://example.org/path">>, ?ENCRYPTED_RESULT),
  AuthHeader = proplists:get_value(<<"authorization">>, Headers),
  {ok, VapidPubKey} = application:get_env(erl_web_push, vapid_public_key),
  JWT = binary:part(AuthHeader, 8, (byte_size(AuthHeader) - byte_size(VapidPubKey) - 12)),
  [JWTHeader, JWTBody, JWTSig] = binary:split(JWT, [<<".">>], [global]),
  Header = jsx:decode(base64_url_decode(JWTHeader)),
  ?assertEqual(#{<<"alg">> => <<"ES256">>, <<"typ">> => <<"JWT">>}, Header),
  Body = jsx:decode(base64_url_decode(JWTBody)),
  ?assertMatch( #{ <<"aud">> := <<"https://example.org">>
                 , <<"sub">> := <<"mailto:development@truqu.com">>
                 , <<"exp">> := _
                 }
              , Body
              ),
  Exp = maps:get(<<"exp">>, Body),
  Now = erlang:system_time(second),
  ?assert(Exp > Now andalso Exp =< (Now + 12 * 3600)),
  <<R:256, S:256>> = base64_url_decode(JWTSig),
  Signature = public_key:der_encode('ECDSA-Sig-Value', {'ECDSA-Sig-Value', R, S}),
  ?assert(crypto:verify( ecdsa
                       , sha256
                       , <<JWTHeader/binary, ".", JWTBody/binary>>
                       , Signature
                       , [base64_url_decode(VapidPubKey), prime256v1]
                       )).

%%==============================================================================================
%% Internal functions
%%==============================================================================================

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
