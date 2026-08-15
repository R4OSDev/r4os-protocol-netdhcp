const r4os = @import("r4os");

const MAGIC_COOKIE = [_]u8{ 0x63, 0x82, 0x53, 0x63 };
const OPTION_MESSAGE_TYPE: u8 = 53;
const OPTION_SERVER_ID: u8 = 54;
const OPTION_REQUESTED_IP: u8 = 50;
const OPTION_SUBNET_MASK: u8 = 1;
const OPTION_ROUTER: u8 = 3;
const OPTION_DNS: u8 = 6;
const OPTION_LEASE_TIME: u8 = 51;
const OPTION_RENEW_TIME: u8 = 58;
const OPTION_REBIND_TIME: u8 = 59;
const OPTION_END: u8 = 255;
const DHCP_FIXED_SIZE: usize = 240;

const MessageType = enum(u8) {
    discover = 1,
    offer = 2,
    request = 3,
    decline = 4,
    ack = 5,
    nak = 6,
    release = 7,
    inform = 8,
};

comptime {
    asm (r4os.r4dev.protocolEntriesAsm("netdhcp_init", "netdhcp_shutdown", "netdhcp_query", "netdhcp_dispatch"));
}

export fn netdhcp_init(api: *const r4os.r4dev.ProtocolApi) callconv(.c) i32 {
    var ctx = r4os.r4dev.ProtocolContext.init(api);
    ctx.logInfo("NETDHCP.R4P init");
    _ = ctx.registerRole("net.dhcp", .net, 0);
    _ = ctx.setStatus(.active, "DHCP R4P active");
    return 0;
}

export fn netdhcp_shutdown() callconv(.c) i32 {
    return 0;
}

export fn netdhcp_query(out: *r4os.abi.ProtocolStatus) callconv(.c) i32 {
    out.* = .{
        .state = @intFromEnum(r4os.abi.ProtocolState.active),
        .flags = 0,
        .last_error = 0,
        .reserved = 0,
        .note = note("DHCP R4P ready"),
    };
    return 0;
}

export fn netdhcp_dispatch(op: u32, in_buffer: *const r4os.abi.ProtocolBuffer, out_buffer: *r4os.abi.ProtocolBuffer) callconv(.c) i32 {
    _ = out_buffer;
    const request = requestFromBuffer(in_buffer) orelse return -2;
    switch (op) {
        r4os.abi.dhcp_op_build_discover => buildDiscover(request),
        r4os.abi.dhcp_op_build_request => buildRequest(request),
        r4os.abi.dhcp_op_handle_message => handleMessage(request),
        r4os.abi.dhcp_op_build_release => buildRelease(request),
        else => return -4,
    }
    return request.result;
}

fn buildDiscover(request: *r4os.abi.DhcpOp) void {
    const msg = buildBase(request) orelse {
        request.result = r4os.abi.dhcp_result_buffer_small;
        return;
    };
    var pos: usize = DHCP_FIXED_SIZE;
    pos = option(msg, pos, OPTION_MESSAGE_TYPE, &[_]u8{@intFromEnum(MessageType.discover)}) orelse {
        request.result = r4os.abi.dhcp_result_buffer_small;
        return;
    };
    pos = end(msg, pos) orelse {
        request.result = r4os.abi.dhcp_result_buffer_small;
        return;
    };
    request.payload_len = @intCast(pos);
    request.message_type = @intFromEnum(MessageType.discover);
    request.flags = r4os.abi.dhcp_flag_discover;
    request.result = r4os.abi.dhcp_result_ok;
}

fn buildRequest(request: *r4os.abi.DhcpOp) void {
    const msg = buildBase(request) orelse {
        request.result = r4os.abi.dhcp_result_buffer_small;
        return;
    };
    var pos: usize = DHCP_FIXED_SIZE;
    pos = option(msg, pos, OPTION_MESSAGE_TYPE, &[_]u8{@intFromEnum(MessageType.request)}) orelse {
        request.result = r4os.abi.dhcp_result_buffer_small;
        return;
    };
    pos = option(msg, pos, OPTION_REQUESTED_IP, &request.requested_ip) orelse {
        request.result = r4os.abi.dhcp_result_buffer_small;
        return;
    };
    pos = option(msg, pos, OPTION_SERVER_ID, &request.server_ip) orelse {
        request.result = r4os.abi.dhcp_result_buffer_small;
        return;
    };
    pos = end(msg, pos) orelse {
        request.result = r4os.abi.dhcp_result_buffer_small;
        return;
    };
    request.payload_len = @intCast(pos);
    request.message_type = @intFromEnum(MessageType.request);
    request.flags = r4os.abi.dhcp_flag_request;
    request.result = r4os.abi.dhcp_result_ok;
}

fn buildRelease(request: *r4os.abi.DhcpOp) void {
    const msg = buildBase(request) orelse {
        request.result = r4os.abi.dhcp_result_buffer_small;
        return;
    };
    copyIp(msg[12..16], request.client_ip);
    var pos: usize = DHCP_FIXED_SIZE;
    pos = option(msg, pos, OPTION_MESSAGE_TYPE, &[_]u8{@intFromEnum(MessageType.release)}) orelse {
        request.result = r4os.abi.dhcp_result_buffer_small;
        return;
    };
    pos = option(msg, pos, OPTION_SERVER_ID, &request.server_ip) orelse {
        request.result = r4os.abi.dhcp_result_buffer_small;
        return;
    };
    pos = end(msg, pos) orelse {
        request.result = r4os.abi.dhcp_result_buffer_small;
        return;
    };
    request.payload_len = @intCast(pos);
    request.message_type = @intFromEnum(MessageType.release);
    request.flags = r4os.abi.dhcp_flag_release;
    request.result = r4os.abi.dhcp_result_ok;
}

fn handleMessage(request: *r4os.abi.DhcpOp) void {
    request.flags = 0;
    if (request.payload_len < DHCP_FIXED_SIZE or request.payload_len > request.payload.len) {
        request.result = r4os.abi.dhcp_result_shape;
        return;
    }
    const payload = request.payload[0..@intCast(request.payload_len)];
    // Only BOOTREPLY/Ethernet replies are valid input for the client.  Keep
    // chaddr in the existing mac field so the kernel can bind a broadcast
    // response to the exact adapter which started the transaction.
    if (payload[0] != 2 or payload[1] != 1 or payload[2] != 6) {
        request.result = r4os.abi.dhcp_result_shape;
        return;
    }
    request.xid = readBe32(payload, 4);
    var mac_index: usize = 0;
    while (mac_index < request.mac.len) : (mac_index += 1) {
        request.mac[mac_index] = payload[28 + mac_index];
    }
    if (!cookieOk(payload)) {
        request.result = r4os.abi.dhcp_result_shape;
        return;
    }
    const typ = optionByte(payload, OPTION_MESSAGE_TYPE) orelse {
        request.result = r4os.abi.dhcp_result_no_type;
        return;
    };
    request.message_type = typ;
    request.offered_ip = readIp(payload, 16);
    request.server_ip = optionIp(payload, OPTION_SERVER_ID) orelse .{0} ** 4;
    request.netmask = optionIp(payload, OPTION_SUBNET_MASK) orelse .{ 255, 255, 255, 0 };
    request.gateway_ip = optionIp(payload, OPTION_ROUTER) orelse request.server_ip;
    request.lease_seconds = optionU32(payload, OPTION_LEASE_TIME) orelse 0;
    request.renew_seconds = optionU32(payload, OPTION_RENEW_TIME) orelse 0;
    request.rebind_seconds = optionU32(payload, OPTION_REBIND_TIME) orelse 0;
    if (optionIp(payload, OPTION_DNS)) |dns_ip| {
        request.dns_ip = dns_ip;
        request.dns_configured = 1;
    } else {
        request.dns_ip = request.server_ip;
        request.dns_configured = if (isZeroIp(request.server_ip)) 0 else 1;
    }
    if (typ == @intFromEnum(MessageType.offer)) {
        request.flags = r4os.abi.dhcp_flag_offer;
        request.result = r4os.abi.dhcp_result_ok;
        return;
    }
    if (typ == @intFromEnum(MessageType.ack)) {
        request.flags = r4os.abi.dhcp_flag_ack | r4os.abi.dhcp_flag_bound;
        request.result = r4os.abi.dhcp_result_ok;
        return;
    }
    if (typ == @intFromEnum(MessageType.nak)) {
        request.flags = r4os.abi.dhcp_flag_nak;
        request.result = r4os.abi.dhcp_result_ok;
        return;
    }
    request.result = r4os.abi.dhcp_result_ignored;
}

fn buildBase(request: *r4os.abi.DhcpOp) ?[]u8 {
    if (request.payload.len < DHCP_FIXED_SIZE + 8) return null;
    var i: usize = 0;
    while (i < request.payload.len) : (i += 1) request.payload[i] = 0;
    request.payload[0] = 1;
    request.payload[1] = 1;
    request.payload[2] = 6;
    writeBe32(request.payload[0..], 4, request.xid);
    writeBe16(request.payload[0..], 10, 0x8000);
    i = 0;
    while (i < 6) : (i += 1) request.payload[28 + i] = request.mac[i];
    request.payload[236] = MAGIC_COOKIE[0];
    request.payload[237] = MAGIC_COOKIE[1];
    request.payload[238] = MAGIC_COOKIE[2];
    request.payload[239] = MAGIC_COOKIE[3];
    return request.payload[0..];
}

fn requestFromBuffer(buffer: *const r4os.abi.ProtocolBuffer) ?*r4os.abi.DhcpOp {
    if (buffer.data == null) return null;
    if (buffer.len < @sizeOf(r4os.abi.DhcpOp)) return null;
    return @ptrCast(@alignCast(buffer.data.?));
}

fn option(buf: []u8, pos: usize, code: u8, data: []const u8) ?usize {
    if (pos + 2 + data.len > buf.len or data.len > 255) return null;
    buf[pos] = code;
    buf[pos + 1] = @intCast(data.len);
    var i: usize = 0;
    while (i < data.len) : (i += 1) buf[pos + 2 + i] = data[i];
    return pos + 2 + data.len;
}

fn end(buf: []u8, pos: usize) ?usize {
    if (pos >= buf.len) return null;
    buf[pos] = OPTION_END;
    return pos + 1;
}

fn cookieOk(payload: []const u8) bool {
    return payload[236] == MAGIC_COOKIE[0] and payload[237] == MAGIC_COOKIE[1] and payload[238] == MAGIC_COOKIE[2] and payload[239] == MAGIC_COOKIE[3];
}

fn optionByte(payload: []const u8, code: u8) ?u8 {
    const data = optionData(payload, code) orelse return null;
    if (data.len != 1) return null;
    return data[0];
}

fn optionIp(payload: []const u8, code: u8) ?[4]u8 {
    const data = optionData(payload, code) orelse return null;
    if (data.len < 4) return null;
    return .{ data[0], data[1], data[2], data[3] };
}

fn optionU32(payload: []const u8, code: u8) ?u32 {
    const data = optionData(payload, code) orelse return null;
    if (data.len != 4) return null;
    return readBe32(data, 0);
}

fn optionData(payload: []const u8, code: u8) ?[]const u8 {
    var pos: usize = DHCP_FIXED_SIZE;
    while (pos < payload.len) {
        const opt = payload[pos];
        if (opt == OPTION_END) return null;
        if (opt == 0) {
            pos += 1;
            continue;
        }
        if (pos + 1 >= payload.len) return null;
        const len = payload[pos + 1];
        if (pos + 2 + len > payload.len) return null;
        if (opt == code) return payload[pos + 2 .. pos + 2 + len];
        pos += 2 + len;
    }
    return null;
}

fn readIp(buf: []const u8, offset: usize) [4]u8 {
    return .{ buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3] };
}

fn copyIp(dst: []u8, src: [4]u8) void {
    var i: usize = 0;
    while (i < 4) : (i += 1) dst[i] = src[i];
}

fn readBe32(buf: []const u8, offset: usize) u32 {
    return (@as(u32, buf[offset]) << 24) |
        (@as(u32, buf[offset + 1]) << 16) |
        (@as(u32, buf[offset + 2]) << 8) |
        @as(u32, buf[offset + 3]);
}

fn isZeroIp(ip: [4]u8) bool {
    return ip[0] == 0 and ip[1] == 0 and ip[2] == 0 and ip[3] == 0;
}

fn writeBe16(buf: []u8, offset: usize, value: u16) void {
    buf[offset] = @intCast(value >> 8);
    buf[offset + 1] = @intCast(value & 0xFF);
}

fn writeBe32(buf: []u8, offset: usize, value: u32) void {
    buf[offset] = @intCast(value >> 24);
    buf[offset + 1] = @intCast((value >> 16) & 0xFF);
    buf[offset + 2] = @intCast((value >> 8) & 0xFF);
    buf[offset + 3] = @intCast(value & 0xFF);
}

fn note(comptime text: []const u8) [64]u8 {
    var out: [64]u8 = .{0} ** 64;
    @memcpy(out[0..text.len], text);
    return out;
}
