local TLSSocket = require "tlssocket"

describe("I/O operations", function()
  it("can be done in blocking mode", function()
    local handle = TLSSocket.new()
    local ok, err = handle:connect("google.com")

    assert.truthy(ok)
    assert.falsy(err)

    local sendBuffer = "GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n"
    local length, err = handle:send(sendBuffer)

    assert.is_true(#sendBuffer == length)

    local msg, err = handle:receive("*l")

    assert.are.same(msg, "HTTP/1.1 200 OK")

    handle:close()
  end)

  it("can be done in non-blocking mode", function()
    local handle = TLSSocket.new()

    local co = coroutine.create(function()
      local ok, err = handle:connect("luajit.org")

      assert.truthy(ok)
      assert.falsy(err)

      local sendBuffer = "GET / HTTP/1.1\r\n\r\n"
      local length, err = handle:send(sendBuffer)

      assert.is_true(#sendBuffer == length)

      local msg, err = handle:receive("*l")

      assert.are.same(msg, "HTTP/1.1 200 OK")

      handle:close()
    end)

    repeat
      local status = coroutine.resume(co)
    until not status
  end)

  it("can read X bytes", function()
    local handle = TLSSocket.new()
    local ok, err = handle:connect("lua.org")

    assert.truthy(ok)
    assert.falsy(err)

    local sendBuffer = "GET / HTTP/1.1\r\nHost: www.lua.org\r\n\r\n"
    local length, err = handle:send(sendBuffer)

    assert.is_true(#sendBuffer == length)

    local msg, err = handle:receive(15)

    assert.is_true(#msg == 15)
    assert.are.same(msg, "HTTP/1.1 200 OK")

    local msg, err = handle:receive(100)
    assert.is_true(#msg == 100)

    handle:close()
  end)
end)