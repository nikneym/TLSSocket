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

local function read(h, n)
  local data, err, part = h:receive(n)
  if data or part then
    return data or part
  end

  return ""
end

local function write(h, s)
  local try_send, err = h:send(s)
  if try_send ~= nil and err == nil then
    return try_send
  end

  if not try_send and err == "timeout" then
    return 0
  end
end

local TLSSocket = {
  version = "0.1.0",
  cfg = tls.newconfig "tls-client"
}
TLSSocket.__index = TLSSocket

function TLSSocket.tcp()
  local handle = socket.tcp()
  local readBuffer = buffer.new(8192)

  return setmetatable({
    handle = handle,
    readBuffer = readBuffer,
    isBlocking = true,
    context = tls.newcontext(TLSSocket.cfg, read, write, handle),
  }, TLSSocket)
end

function TLSSocket:setBlocking(state)
  assert(type(state) == "boolean")

  if state == false then
    self.isBlocking = false
    return self.handle:settimeout(0)
  end

  self.isBlocking = true
  return self.handle:settimeout()
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
  return self.handle:connect(host, port or 443)
end

function TLSSocket:send(str)
  local msg, err = self.context:write(str)
  if msg then
    return msg, nil
  end

  return nil, "timeout"
end

local function socket_read(self, length)
  local bufferLen = #self.readBuffer

  -- got enough bytes in the buffer
  if bufferLen >= length then
    return self.readBuffer:get(length), nil
  end

  -- not enough bytes, receive 'till get the full
  local msg, err = self.context:read(length - bufferLen)
  if msg then
    self.readBuffer:put(msg)

    if #self.readBuffer == length then
      return self.readBuffer:get(length), nil
    end
  end

  return nil, "timeout"
end

-- TODO: refactor as a coroutine(?)
local function socket_read_line(self)
  local bufferLen = #self.readBuffer

  if bufferLen == 0 then
    local msg, err = self.context:read(8192)

    -- got message, put it in a temporary buffer
    if msg then
      local len = #msg

      local tempBuffer = buffer.new(len)
      tempBuffer:set(msg)
      local ptr = tempBuffer:ref()

      -- search if line feed exists
      local line
      for i = 0, len do
        if ptr[i] == 10 then
          line = tempBuffer:get(i)
          tempBuffer:skip(1)
          break
        end

        -- TODO: NULL safety for `ptr[i + 1]`
        if ptr[i] == 13 and ptr[i + 1] == 10 then
          line = tempBuffer:get(i)
          tempBuffer:skip(2)
          break
        end
      end

      -- put the rest back to the big buffer
      self.readBuffer:put(tempBuffer)

      -- found line feed
      if line then
        return line, nil
      end
    end

    return nil, "timeout"
  end

  -- already have some bytes in the buffer
  if bufferLen > 0 then
    local ptr = self.readBuffer:ref()

    local line
    for i = 0, bufferLen do
      if ptr[i] == 10 then
        line = self.readBuffer:get(i)
        self.readBuffer:skip(1)
        break
      end

      -- TODO: NULL safety for `ptr[i + 1]`
      if ptr[i] == 13 and ptr[i + 1] == 10 then
        line = self.readBuffer:get(i)
        self.readBuffer:skip(2)
        break
      end
    end

    -- found line feed
    if line then
      return line, nil
    end

    local msg, err = self.context:read(8192)
    if msg then
      self.readBuffer:put(msg)
    end

    return nil, "timeout"
  end

  error "unreachable"
end

-- TODO: Support '*a' (read all) pattern
function TLSSocket:receive(pattern)
  pattern = pattern or "*l"

  if type(pattern) == "number" then
    return socket_read(self, pattern)
  end

  if pattern == "*l" then
    return socket_read_line(self)
  end

  error "unreachable"
end

return TLSSocket