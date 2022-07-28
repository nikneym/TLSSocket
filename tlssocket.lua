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
local picodnsOk, picodns = pcall(require, "picodns")

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

-- create a picodns resolver if exists
if picodnsOk then
  TLSSocket.resolver = picodns.newResolver()
end

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

function TLSSocket:connect(host, port)
  -- for host name verification
  self.context:sethostname(host)

  -- if called in a coroutine, make this socket non-blocking
  if co_is_yieldable() then
    if self.handle:gettimeout() ~= 0 then
      self.handle:settimeout(0)
    end
  end

  -- resolve host address with picodns if exists
  if picodnsOk then
    local answers, err = TLSSocket.resolver:query(host)
    if err then
      return false, err
    end

    host = answers[1].content
  end

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
  -- got enough bytes in the buffer
  if #self.readBuffer >= length then
    return self.readBuffer:get(length), nil
  end

  -- not enough bytes, receive 'till get the full
  local total = length
  repeat
    local msg, err = self.context:read(length - #self.readBuffer)
    if msg then
      self.readBuffer:put(msg)
    end

    if co_is_yieldable() then
      co_yield()
    end
  until #self.readBuffer >= length

  return self.readBuffer:get(total), nil
end

local function read_line_zero_buffer(self)
  local msg, err
  repeat
    msg, err = self.context:read(8192)
    if co_is_yieldable() then
      co_yield()
    end
  until msg

  local msgLen = #msg

  -- temporary buffer for searching line
  local tempBuffer = buffer.new(msgLen)
  tempBuffer:set(msg)

  local ptr = tempBuffer:ref()

  local line
  for i = 0, msgLen do
    -- found a line feed '\n'
    if ptr[i] == 10 then
      if ptr[i - 1] == 13 then -- '\r'
        line = tempBuffer:get(i - 1)
        tempBuffer:skip(2)
        break
      end

      line = tempBuffer:get(i)
      tempBuffer:skip(1)
      break
    end
  end

  -- put the rest back to buffer
  self.readBuffer:put(tempBuffer)
  tempBuffer:free()

  if line then
    return line, nil
  end

  return nil, "line not found"
end

local function read_line_filled_buffer(self)
  local ptr = self.readBuffer:ref()

  local line
  for i = 0, #self.readBuffer do
    if ptr[i] == 10 then
      if ptr[i - 1] == 13 then
        line = self.readBuffer:get(i - 1)
        self.readBuffer:skip(2)
        break
      end

      line = self.readBuffer:get(i)
      self.readBuffer:skip(1)
      break
    end
  end

  if line then
    return line, nil
  end

  -- TODO: optimize and cleanup
  local msg, err
  repeat
    msg, err = self.context:read(8192)
    if co_is_yieldable() then
      co_yield()
    end
  until msg
  self.readBuffer:put(msg)

  return nil, "failed to read line"
end

local function read_by_line(self)
  local bufferLen = #self.readBuffer

  -- got bytes in the buffer
  if bufferLen > 0 then
    local line, err = read_line_filled_buffer(self)
    if err then
      return read_by_line(self)
    end

    return line, nil
  end

  -- no bytes in the buffer, let's read some
  if bufferLen == 0 then
    local line, err = read_line_zero_buffer(self)
    if err then
      return read_by_line(self)
    end

    return line, nil
  end
end

function TLSSocket:receive(pattern)
  pattern = pattern or "*l"

  if type(pattern) == "number" then
    return read_by_length(self, pattern)
  end

  -- work in progress
  if pattern == "*l" then
    return read_by_line(self)
  end
end

return TLSSocket