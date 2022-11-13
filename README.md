TLSSocket
===========
Lightweight, non-blocking SSL/TLS wrapper for LuaSocket

Why this module exists?
===========
As Lua community, I think we can all agree that LuaSocket is problematic. It doesn't truly support non-blocking connect calls, `receive` method might seem timed out but give you an unexpected buffer as a third argument(?), no built-in TLS context...

But still, it's the only networking module that is cross platform and we don't have a better choice. So this module tries to fix the issues mentioned earlier.

Features
===========
* SSL/TLS support
* Optionally non-blocking
* Can be integrated to event loops easily, thanks to it's coroutine respective style
* Does buffered read in order to create less garbage
* Has matching API with LuaSocket

How-to
===========
```lua
local TLSSocket = require "tlssocket"

-- create a new socket and connect to google.com:443
local sock = TLSSocket.new()
local ok, err = sock:connect("google.com")
if err then
  error(err)
end

-- send a simple HTTP request
local len, err = sock:send("GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n")
if err then
  error(err)
end

-- read HTTP response headers
repeat
  local msg, err = sock:receive("*l")
  if err then
    error(err)
  end

  print(msg)
until msg == ""

-- shutdown
sock:close()
```

Dependencies
===========
* [LuaSocket](https://github.com/lunarmodules/luasocket)
* [lua-mbedtls](https://github.com/neoxic/lua-mbedtls)
* [picodns](https://github.com/nikneym/picodns) (optional)
* String Buffer API (already included in LuaJIT)

Tests
===========
You need [busted](http://olivinelabs.com/busted) in order to run the tests.

License
===========
MIT License, [check out](https://github.com/nikneym/tlssocket.lua/blob/main/LICENSE).