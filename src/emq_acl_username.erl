%%--------------------------------------------------------------------
%% Copyright 2017 Leonardo Rossi <leonardo.rossi@studenti.unipr.it>
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

-module(emq_acl_username).

-author('Leonardo Rossi <leonardo.rossi@studenti.unipr.it>').

-include_lib("emqttd/include/emqttd.hrl").
-include_lib("emq_auth_username/include/emq_auth_username.hrl").

-behaviour(emqttd_acl_mod).

-export([init/1, check_acl/2, reload_acl/1, description/0]).

-type appctx() :: map().
-type topic()  :: binary().


%%--------------------------------------------------------------------
%% ACL callbacks
%%--------------------------------------------------------------------

-spec init(appctx()) -> {ok, appctx()}.
init(_) -> {ok, #{}}.

-spec check_acl({mqtt_client(), pubsub(), topic()}, appctx()) ->
  allow | deny | ignore.
check_acl({#mqtt_client{username = Username}, _PubSub, Topic}, _) ->
  case mnesia:dirty_read(?AUTH_USERNAME_TAB, Username) of
    [] -> ignore;
    [#?AUTH_USERNAME_TAB{topic = Topic}] -> allow;
    _Rest -> ignore
  end.

-spec reload_acl(appctx()) -> ok | {error, appctx()}.
reload_acl(_AppCtx) ->
  ok.

-spec description() -> string().
description() ->
  "ACL module to handle JOINS by Esenshub".
