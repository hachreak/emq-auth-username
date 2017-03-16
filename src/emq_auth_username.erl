%%--------------------------------------------------------------------
%% Copyright 2017 Leonardo Rossi <leonardo.rossi@studenti.unipr.it>
%%
%% Copyright (c) 2013-2017 EMQ Enterprise, Inc. (http://emqtt.io)
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%--------------------------------------------------------------------

-module(emq_auth_username).

-include_lib("emqttd/include/emqttd.hrl").
-include_lib("emqttd/include/emqttd_cli.hrl").
-include_lib("emq_auth_username/include/emq_auth_username.hrl").

%% CLI callbacks
-export([cli/1]).

-behaviour(emqttd_auth_mod).

-export([is_enabled/0]).

-export([add_user/3, remove_user/1, lookup_user/1, all_users/0]).

%% emqttd_auth callbacks
-export([init/1, check/3, description/0]).

%%--------------------------------------------------------------------
%% CLI
%%--------------------------------------------------------------------

cli(["list"]) ->
    if_enabled(fun() ->
        Usernames = mnesia:dirty_all_keys(?AUTH_USERNAME_TAB),
        [?PRINT("~s~n", [Username]) || Username <- Usernames]
    end);

cli(["add", Username, Password, Topic]) ->
    if_enabled(fun() ->
        Ret = add_user(iolist_to_binary(Username), iolist_to_binary(Password),
                       iolist_to_binary(Topic)),
        ?PRINT("~p~n", [Ret])
    end);

cli(["del", Username]) ->
    if_enabled(fun() ->
        ?PRINT("~p~n", [remove_user(iolist_to_binary(Username))])
    end);

cli(_) ->
    ?USAGE([{"users list", "List users"},
            {"users add <Username> <Password> <Topic>", "Add User"},
            {"users del <Username>", "Delete User"}]).

if_enabled(Fun) ->
    case is_enabled() of
        true  -> Fun();
        false -> hint()
    end.

hint() ->
  ?PRINT_MSG(
    "Please './bin/emqttd_ctl plugins load emq_auth_username' first.~n").

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

is_enabled() ->
    lists:member(?AUTH_USERNAME_TAB, mnesia:system_info(tables)).

%% @doc Add User
-spec(add_user(binary(), binary(), binary()) -> ok | {error, any()}).
add_user(Username, Password, Topic) ->
    User = #?AUTH_USERNAME_TAB{
        username = Username, password = hash(Password), topic = Topic},
    ret(mnesia:transaction(fun insert_user/1, [User])).

insert_user(User = #?AUTH_USERNAME_TAB{username = Username}) ->
    case mnesia:read(?AUTH_USERNAME_TAB, Username) of
        []    -> mnesia:write(User);
        [_|_] -> mnesia:abort(existed)
    end.

add_default_user(Username, Password, Topic) when is_atom(Username) ->
    add_default_user(atom_to_list(Username), Password, Topic);

add_default_user(Username, Password, Topic) ->
    add_user(iolist_to_binary(Username), iolist_to_binary(Password),
             iolist_to_binary(Topic)).

%% @doc Lookup user by username
-spec(lookup_user(binary()) -> list()).
lookup_user(Username) ->
    mnesia:dirty_read(?AUTH_USERNAME_TAB, Username).

%% @doc Remove user
-spec(remove_user(binary()) -> ok | {error, any()}).
remove_user(Username) ->
    ret(mnesia:transaction(
          fun mnesia:delete/1, [{?AUTH_USERNAME_TAB, Username}])).

ret({atomic, ok})     -> ok;
ret({aborted, Error}) -> {error, Error}.

%% @doc All usernames
-spec(all_users() -> list()).
all_users() -> mnesia:dirty_all_keys(?AUTH_USERNAME_TAB).

%%--------------------------------------------------------------------
%% emqttd_auth_mod callbacks
%%--------------------------------------------------------------------

init(Userlist) ->
    ok = emqttd_mnesia:create_table(?AUTH_USERNAME_TAB, [
            {disc_copies, [node()]},
            {attributes, record_info(fields, ?AUTH_USERNAME_TAB)}]),
    ok = emqttd_mnesia:copy_table(?AUTH_USERNAME_TAB, disc_copies),
    lists:foreach(fun({Username, Password, Topic}) ->
                      add_default_user(Username, Password, Topic)
                  end, Userlist),
    emqttd_ctl:register_cmd(users, {?MODULE, cli}, []),
    {ok, undefined}.

check(#mqtt_client{username = undefined}, _Password, _Opts) -> ignore;
check(_User, undefined, _Opts) -> ignore;
check(#mqtt_client{username = Username}, Password, _Opts) ->
    case mnesia:dirty_read(?AUTH_USERNAME_TAB, Username) of
        [] ->
            ignore;
        [#?AUTH_USERNAME_TAB{password = <<Salt:4/binary, Hash/binary>>}] ->
            case Hash =:= md5_hash(Salt, Password) of
                true -> ok;
                false -> ignore
            end
    end.

description() ->
    "Username password authenticationi to a topic module".

%%--------------------------------------------------------------------
%% Internal functions
%%--------------------------------------------------------------------

hash(Password) ->
    SaltBin = salt(), <<SaltBin/binary, (md5_hash(SaltBin, Password))/binary>>.

md5_hash(SaltBin, Password) ->
    erlang:md5(<<SaltBin/binary, Password/binary>>).

salt() ->
    emqttd_time:seed(), Salt = rand:uniform(16#ffffffff), <<Salt:32>>.

