local TLSSocket = require "tlssocket"

describe("Connections", function()
  it("can be run in blocking mode", function()
    local handle = TLSSocket.new()
    local ok, err = handle:connect("google.com")

    assert.truthy(ok)
    assert.falsy(err)

    handle:close()
  end)

  it("can be run in non-blocking mode", function()
    local handle = TLSSocket.new()

    local co = coroutine.create(function()
      local ok, err = handle:connect("cloudflare.com")

      assert.truthy(ok)
      assert.falsy(err)

      handle:close()
    end)

    repeat
      local status = coroutine.resume(co)
    until not status
  end)
end)