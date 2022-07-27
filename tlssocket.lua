--[[
MIT License

Copyright (c) 2022 nikneym

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
]]

local socket = require "socket"
local buffer = require "string.buffer"
local tls = require "mbedtls.ssl"
local ffi = require "ffi"
local co_is_yieldable = coroutine.isyieldable
local co_yield = coroutine.yield

local function read(h, n)
  local data, err, part = h:receive(n)
  if data or part then
    return data or part
  end

  return "", err
end

local function write(h, s)
  local bytes, err = h:send(s)
  if bytes ~= nil and err == nil then
    return bytes
  end

  if not bytes or bytes < #s then
    return 0, err
  end
end

local TLSSocket = {
  version = "0.1.0",
  cfg = tls.newconfig "tls-client"
}
TLSSocket.__index = TLSSocket

function TLSSocket.new()
  local handle = socket.tcp()

  return setmetatable({
    handle = handle,
    readBuffer = buffer.new(8192),
    context = tls.newcontext(TLSSocket.cfg, read, write, handle),
  }, TLSSocket)
end

function TLSSocket:__tostring()
  return tostring(self.handle)
end

function TLSSocket:close()
  self.readBuffer:free()
  self.context:reset()
  self.handle:close()
end

-- FIX: use picodns for non-blocking connect call
function TLSSocket:connect(host, port)
  -- if called in a coroutine, make this socket non-blocking
  if co_is_yieldable() then
    if self.handle:gettimeout() ~= 0 then
      self.handle:settimeout(0)
    end
  end

  -- for host name verification
  self.context:sethostname(host)

  repeat
    local ok, err = self.handle:connect(host, port or 443)
    if co_is_yieldable() then
      co_yield()
    end
  until ok == 1

  return true, nil
end

function TLSSocket:send(str)
  if co_is_yieldable() then
    local len = #str
    repeat
      local bytesWritten, err = self.context:write(str)
      co_yield()
    until bytesWritten == len

    return len, nil
  end

  return self.context:write(str)
end

local function read_by_length(self, length)
  local bufferLen = #self.readBuffer

  -- got enough bytes in the buffer
  if bufferLen >= length then
    return self.readBuffer:get(length), nil
  end

  -- not enough bytes, receive 'till get the full
  local receivedLength = 0
  while length > receivedLength do
    local msg, err = self.context:read(length - receivedLength)
    if msg then
      self.readBuffer:put(msg)
      receivedLength = receivedLength + #msg
    end

    if co_is_yieldable() then
      co_yield()
    end
  end

  return self.readBuffer:get(length), nil
end

function TLSSocket:receive(pattern)
  pattern = pattern or "*l"

  if type(pattern) == "number" then
    return read_by_length(self, pattern)
  end

  if pattern == "*l" then
    error "not implemented yet"
  end
end

return TLSSocket