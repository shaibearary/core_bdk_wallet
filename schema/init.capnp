# Copyright (c) 2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

@0xf2c5cfa319406aa6;

using Cxx = import "c++.capnp";
$Cxx.namespace("ipc::capnp::messages");

using Proxy = import "/proxy.capnp";
$Proxy.include("interfaces/chain.h");
$Proxy.include("interfaces/echo.h");
$Proxy.include("interfaces/init.h");
$Proxy.include("interfaces/mining.h");
$Proxy.includeTypes("ipc/capnp/init-types.h");

using Chain = import "chain.capnp";
using Echo = import "echo.capnp";
using Mining = import "mining.capnp";

interface Init $Proxy.wrap("interfaces::Init") {
    construct @0 (threadMap: Proxy.ThreadMap) -> (threadMap :Proxy.ThreadMap);
    makeEcho @1 (context :Proxy.Context) -> (result :Echo.Echo);
    makeMining @2 (context :Proxy.Context) -> (result :Mining.Mining);
    makeChain @3 (context :Proxy.Context) -> (result :Chain.Chain);
}
