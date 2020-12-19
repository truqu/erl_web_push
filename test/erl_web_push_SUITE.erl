-module(erl_web_push_SUITE).

-export([all/0]).

%% Tests
-export([ encrypt_correctly_encrypts_known_good_values_1/1
        , encrypt_correctly_encrypts_known_good_values_2/1
        ]).

-spec all() -> [atom()].
all() ->
  [ encrypt_correctly_encrypts_known_good_values_1
  , encrypt_correctly_encrypts_known_good_values_2
  ].

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
  ClientPubKey =
    << "BOLcHOg4ajSHR6BjbSBeX_6aXjMu1V5RrUYXqyV_FqtQSd8RzdU1gkMv1DlRPDIUtFK6Nd16Jql0eSzyZh4V2uc"
    >>,
  ClientAuthToken = <<"r9kcFt8-4Q6MnMjJHqJoSQ">>,
  {ok, {Enc, _Salt, _PubKey}} =
    erl_web_push:encrypt(Message, ClientPubKey, ClientAuthToken, Salt, ServerPub, ServerPriv),
  Enc = base64:decode(<<"qbU60BXbSk+PKtJPKD3z9KEs3le4+23LJkC04+2E">>).

-spec encrypt_correctly_encrypts_known_good_values_2(any()) -> any().
encrypt_correctly_encrypts_known_good_values_2(_) ->
  %% Values from https://tools.ietf.org/html/rfc8291
  Salt = base64:decode(<<"DGv6ra1nlYgDCS1FRnbzlw==">>),
  ServerPub = base64:decode(<< "BP4z9KsN6nGRTbVYI/c7VJSPQTBtkgcy27mlmlMoZIIg"
                               "Dll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8="
                            >>),
  ServerPriv = base64:decode(<<"yfWPiYE+n46HLnH0KqZOF1fJJU3MYrct3AELtAQ+oRw=">>),
  Message = <<"When I grow up, I want to be a watermelon">>,
  ClientPubKey =
    << "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
    >>,
  ClientAuthToken = <<"BTBZMqHH6r4Tts7J_aSIgg">>,
  {ok, {Enc, _Salt, _PubKey}} =
    erl_web_push:encrypt(Message, ClientPubKey, ClientAuthToken, Salt, ServerPub, ServerPriv),
  Expected =
    <<"8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI/0LpXMuGvnzQ==">>,
  Enc = base64:decode(Expected).

%%==============================================================================================
%% Internal functions
%%==============================================================================================


%% Local variables:
%% mode: erlang
%% erlang-indent-level: 2
%% indent-tabs-mode: nil
%% fill-column: 96
%% coding: utf-8
%% End:
