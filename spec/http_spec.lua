local TLSSocket = require "init"

describe("HTTP requests", function()
  it("can be read by Content-Length", function()
    local handle = TLSSocket.new()
    local ok, err = handle:connect("lua.org")

    assert.truthy(ok)
    assert.falsy(err)

    local sendBuffer = "GET / HTTP/1.1\r\nHost: www.lua.org\r\n\r\n"
    local length, err = handle:send(sendBuffer)

    local contentLength
    repeat
      local msg, err = handle:receive("*l")
      if not contentLength then
        local len = msg:match("Content%-Length%: (.+)")
        contentLength = tonumber(len)
      end
    until msg == ""

    assert.truthy(contentLength)

    local msg, err = handle:receive(contentLength)

    assert.truthy(msg)
    assert.falsy(err)

    handle:close()
  end)

  it("can be read as chunked", function()
    local handle = TLSSocket.new()
    local ok, err = handle:connect("google.com")

    assert.truthy(ok)
    assert.falsy(err)

    local sendBuffer = "GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n"
    local length, err = handle:send(sendBuffer)

    assert.is_true(#sendBuffer == length)

    local isTranferEncoding
    repeat
      local msg, err = handle:receive("*l")
      if not isTranferEncoding and msg:find("^Transfer%-Encoding") then
        isTranferEncoding = true
      end
    until msg == ""

    assert.truthy(isTranferEncoding)

    repeat
      local msg, err = handle:receive("*l")
      local len = tonumber(msg, 16)

      msg, err = handle:receive(len)
      assert.is_true(#msg == len)

      handle:receive("*l")
    until len == 0

    handle:close()
  end)
end)