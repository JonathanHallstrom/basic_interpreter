const std = @import("std");

var stdin = std.io.getStdIn().reader();
var stdout = std.io.getStdOut().writer();

var io_buf: [1 << 20]u8 align(64) = undefined;
var fbstream = std.io.fixedBufferStream(&io_buf);
var output_writer = fbstream.writer();

var variables: [26]i32 align(64) = .{0} ** 26;

var string_buf: [1 << 20]u8 align(64) = undefined;
var string_buf_write_idx: usize = 0;

var ops: [1024]Operation = undefined;
// at most 2 immediates per line
var immediates: [2 * ops.len]i32 align(64) = .{0} ** (2 * ops.len);
var immediate_count: usize = 0;

const Instruction = enum {
    Let,
    If,
    Print,
    PrintLn,
};

const Opcode = enum {
    LoadImm,

    Add,
    Sub,
    Mul,
    Div,

    BranchEq,
    BranchNe,
    BranchLe,
    BranchLq,
    BranchGr,
    BranchGq,

    PrintVar,
    PrintLnVar,

    PrintStr,
    PrintLnStr,

    Exit,
};

const Operation = struct {
    opcode: Opcode,
    data: OperationData,

    const OperationData = struct {
        first_operand: union {
            operand: *i32,
            str_ptr: [*]u8,
        },
        second_operand: union {
            operand: *i32,
            str_len: usize,
            unused: void,
        },
        third_operand: union {
            next_instruction: usize,
            operand: *i32,
            unused: void,
        },
    };
};

inline fn funcFromOpcode(opcode: Opcode) *const fn (usize) void {
    const funcs = [_]*const fn (usize) void{
        &loadImm,
        &add,
        &sub,
        &mul,
        &div,
        &branchEq,
        &branchNe,
        &branchLe,
        &branchLq,
        &branchGr,
        &branchGq,
        &printVar,
        &printLnVar,
        &printStr,
        &printLnStr,
        &exitInterpreter,
    };
    return funcs[@intFromEnum(opcode)];
}

inline fn tailcallNextInstruction(ip: usize) void {
    return @call(.always_tail, funcFromOpcode(ops[ip].opcode), .{ip});
}

fn loadImm(ip: usize) void {
    const operation = ops[ip];
    const data = operation.data;
    data.first_operand.operand.* = data.second_operand.operand.*;
    return tailcallNextInstruction(ip + 1);
}
fn add(ip: usize) void {
    const operation = ops[ip];
    const data = operation.data;
    data.first_operand.operand.* = data.second_operand.operand.* +% data.third_operand.operand.*;
    return tailcallNextInstruction(ip + 1);
}
fn sub(ip: usize) void {
    const operation = ops[ip];
    const data = operation.data;
    data.first_operand.operand.* = data.second_operand.operand.* -% data.third_operand.operand.*;
    return tailcallNextInstruction(ip + 1);
}
fn mul(ip: usize) void {
    const operation = ops[ip];
    const data = operation.data;
    data.first_operand.operand.* = data.second_operand.operand.* *% data.third_operand.operand.*;
    return tailcallNextInstruction(ip + 1);
}
fn div(ip: usize) void {
    const operation = ops[ip];
    const data = operation.data;
    data.first_operand.operand.* = @divTrunc(data.second_operand.operand.*, data.third_operand.operand.*);
    return tailcallNextInstruction(ip + 1);
}
fn branchEq(ip: usize) void {
    const operation = ops[ip];
    const data = operation.data;
    return tailcallNextInstruction(if (data.first_operand.operand.* == data.second_operand.operand.*) data.third_operand.next_instruction else ip + 1);
}
fn branchNe(ip: usize) void {
    const operation = ops[ip];
    const data = operation.data;
    return tailcallNextInstruction(if (data.first_operand.operand.* != data.second_operand.operand.*) data.third_operand.next_instruction else ip + 1);
}
fn branchLe(ip: usize) void {
    const operation = ops[ip];
    const data = operation.data;
    return tailcallNextInstruction(if (data.first_operand.operand.* < data.second_operand.operand.*) data.third_operand.next_instruction else ip + 1);
}
fn branchLq(ip: usize) void {
    const operation = ops[ip];
    const data = operation.data;
    return tailcallNextInstruction(if (data.first_operand.operand.* <= data.second_operand.operand.*) data.third_operand.next_instruction else ip + 1);
}
fn branchGr(ip: usize) void {
    const operation = ops[ip];
    const data = operation.data;
    return tailcallNextInstruction(if (data.first_operand.operand.* > data.second_operand.operand.*) data.third_operand.next_instruction else ip + 1);
}
fn branchGq(ip: usize) void {
    const operation = ops[ip];
    const data = operation.data;
    return tailcallNextInstruction(if (data.first_operand.operand.* >= data.second_operand.operand.*) data.third_operand.next_instruction else ip + 1);
}
fn printVar(ip: usize) void {
    const operation = ops[ip];
    output_writer.print("{}", .{operation.data.first_operand.operand.*}) catch unreachable;
    return tailcallNextInstruction(ip + 1);
}
fn printLnVar(ip: usize) void {
    const operation = ops[ip];
    output_writer.print("{}\n", .{operation.data.first_operand.operand.*}) catch unreachable;
    return tailcallNextInstruction(ip + 1);
}
fn printStr(ip: usize) void {
    const operation = ops[ip];
    output_writer.print("{s}", .{operation.data.first_operand.str_ptr[0..operation.data.second_operand.str_len]}) catch unreachable;
    return tailcallNextInstruction(ip + 1);
}
fn printLnStr(ip: usize) void {
    const operation = ops[ip];
    output_writer.print("{s}\n", .{operation.data.first_operand.str_ptr[0..operation.data.second_operand.str_len]}) catch unreachable;
    return tailcallNextInstruction(ip + 1);
}
fn exitInterpreter(ip: usize) void {
    _ = ip;
    return;
}

pub fn main() !void {
    const t1 = std.time.Instant.now() catch unreachable;
    const read_bytes = stdin.readAll(&io_buf) catch unreachable;
    const t2 = std.time.Instant.now() catch unreachable;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var line_numbers = std.ArrayList(u32).init(allocator);
    defer line_numbers.deinit();

    var it: usize = 0;
    const line_keep = comptime blk: {
        var res: [65]@Vector(64, u8) = undefined;
        res[0] = @splat(0);
        for (0..64) |i| {
            res[i + 1] = res[i];
            res[i + 1][i] = 255;
        }
        break :blk res;
    };

    const ParsedOperation = struct {
        line: u32,
        operation: Operation,

        fn cmp(_: void, left: @This(), right: @This()) bool {
            return left.line < right.line;
        }
    };
    var operations = std.ArrayList(ParsedOperation).init(allocator);
    defer operations.deinit();

    while (it < read_bytes) {
        // longest possible line which isn't a print is '1000000000 if 1000000000 <= 1000000000 THEN GOTO 1000000000', which has length 59, so we load 64 bytes, aka one cache line
        // print with long strings is handled separately
        var first_64_bytes: @Vector(64, u8) = io_buf[it..][0..64].*;

        const newlines: @Vector(64, u8) = @splat('\n');
        const spaces: @Vector(64, u8) = @splat(' ');
        const equal_newline = first_64_bytes == newlines;
        const newline_msk: u64 = @bitCast(equal_newline);
        var line_length: usize = @ctz(newline_msk);

        const keep_mask = line_keep[line_length];
        first_64_bytes &= keep_mask;
        first_64_bytes |= ~keep_mask & spaces;

        const cleaned_line: [64]u8 = first_64_bytes;

        const equal_space = first_64_bytes == spaces;
        var msk: u64 = @bitCast(equal_space);

        const get_token_length = struct {
            fn impl(mask: *u64) u8 {
                const res = @ctz(mask.*);
                mask.* >>= @truncate(res + 1);
                return res;
            }
        }.impl;

        const number_length = get_token_length(&msk);
        const first_token_length = get_token_length(&msk);

        const instruction_from_length = comptime blk: {
            var instructions: [8]Instruction = .{.If} ** 8;
            instructions[2] = .If;
            instructions[3] = .Let;
            instructions[5] = .Print;
            instructions[7] = .PrintLn;
            break :blk instructions;
        };
        const instruction = instruction_from_length[first_token_length];

        var line_num: u32 = 0;
        for (0..number_length) |i| line_num = line_num * 10 + cleaned_line[i] - '0';

        line_numbers.append(line_num) catch unreachable;

        const get_operand_pointer = struct {
            fn impl(slice: []const u8) *i32 {
                var res: *i32 = undefined;
                if ('A' <= slice[0] and slice[0] <= 'Z') {
                    res = &variables[slice[0] - 'A'];
                } else {
                    immediates[immediate_count] = std.fmt.parseInt(i32, slice, 10) catch unreachable;
                    res = &immediates[immediate_count];
                    immediate_count += 1;
                }
                return res;
            }
        }.impl;

        switch (instruction) {
            .If => {
                const left_operand_length = get_token_length(&msk);
                const operator_length = get_token_length(&msk);
                const right_operand_length = get_token_length(&msk);
                const then_length = get_token_length(&msk);
                std.debug.assert(then_length == 4);
                const goto_length = get_token_length(&msk);
                std.debug.assert(goto_length == 4);
                const dest_length = get_token_length(&msk);

                const left_operand_idx = number_length + 1 + first_token_length + 1;
                const operator_idx = left_operand_idx + left_operand_length + 1;
                const right_operand_idx = operator_idx + operator_length + 1;
                const dest_idx = right_operand_idx + right_operand_length + 1 + then_length + 1 + goto_length + 1;

                const left_operand = cleaned_line[left_operand_idx..][0..left_operand_length];
                const operator = cleaned_line[operator_idx..][0..operator_length];
                const right_operand = cleaned_line[right_operand_idx..][0..right_operand_length];
                const dest = cleaned_line[dest_idx..][0..dest_length];

                const left_operand_pointer: *i32 = get_operand_pointer(left_operand); // issue
                const right_operand_pointer: *i32 = get_operand_pointer(right_operand);
                const dest_value = std.fmt.parseUnsigned(usize, dest, 10) catch unreachable;
                const opcode: Opcode = switch (operator[0]) {
                    '=' => .BranchEq,
                    '<' => if (operator.len == 1) .BranchLe else if (operator[1] == '=') .BranchLq else .BranchNe,
                    '>' => if (operator.len == 1) .BranchGr else .BranchGq,
                    else => unreachable,
                };
                operations.append(ParsedOperation{
                    .line = line_num,
                    .operation = .{
                        .opcode = opcode,
                        .data = .{
                            .first_operand = .{ .operand = left_operand_pointer },
                            .second_operand = .{ .operand = right_operand_pointer },
                            .third_operand = .{ .next_instruction = dest_value },
                        },
                    },
                }) catch unreachable;
            },
            .Let => {
                // find lengths of all the mandatory parts
                const assignment_target_length = get_token_length(&msk);
                const assignment_operator_length = get_token_length(&msk);
                std.debug.assert(assignment_operator_length == 1); // should always be one because this should be an '='
                const left_operand_length = get_token_length(&msk);

                // 0 or 1, depending on whether one exists
                const operator_length = get_token_length(&msk);

                // find start indices of all the mandatory parts
                const assignment_target_idx = number_length + 1 + first_token_length + 1;
                const assignment_operator_idx = assignment_target_idx + assignment_target_length + 1;
                const left_operand_idx = assignment_operator_idx + assignment_operator_length + 1;

                const assignment_target = cleaned_line[assignment_target_idx..][0..assignment_target_length];
                const left_operand = cleaned_line[left_operand_idx..][0..left_operand_length];

                const assignmment_target_pointer: *i32 = get_operand_pointer(assignment_target);
                const left_operand_pointer: *i32 = get_operand_pointer(left_operand);

                if (operator_length > 0) {
                    const right_operand_length = get_token_length(&msk);

                    const operator_idx = left_operand_idx + left_operand_length + 1;
                    const right_operand_idx = operator_idx + operator_length + 1;

                    const operator = cleaned_line[operator_idx..][0..operator_length][0];
                    const right_operand = cleaned_line[right_operand_idx..][0..right_operand_length];
                    const right_operand_pointer: *i32 = get_operand_pointer(right_operand);

                    const opcode: Opcode = switch (operator) {
                        '+' => .Add,
                        '-' => .Sub,
                        '*' => .Mul,
                        '/' => .Div,
                        else => unreachable,
                    };

                    operations.append(.{
                        .line = line_num,
                        .operation = .{
                            .opcode = opcode,
                            .data = .{
                                .first_operand = .{ .operand = assignmment_target_pointer },
                                .second_operand = .{ .operand = left_operand_pointer },
                                .third_operand = .{ .operand = right_operand_pointer },
                            },
                        },
                    }) catch unreachable;
                } else {
                    operations.append(.{
                        .line = line_num,
                        .operation = .{
                            .opcode = .LoadImm,
                            .data = .{
                                .first_operand = .{ .operand = assignmment_target_pointer },
                                .second_operand = .{ .operand = left_operand_pointer },
                                .third_operand = .{ .unused = {} },
                            },
                        },
                    }) catch unreachable;
                }
            },
            .Print,
            => {
                const start_print = number_length + 1 + first_token_length + 1;
                if (cleaned_line[start_print] == '"') {

                    // this is somewhat subtle, line could be longer than 64 bytes so we look at the whole buffer and update line length accordingly
                    const end_print = start_print + 1 + std.mem.indexOfScalar(u8, io_buf[it..][start_print + 1 ..], '"').?;
                    line_length = end_print + 1;

                    // copy strings to separate buffer, io_buf will be overwritten
                    const str = io_buf[it..][start_print + 1 .. end_print];
                    @memcpy(string_buf[string_buf_write_idx..][0..str.len], str);
                    const str_ptr = string_buf[string_buf_write_idx..].ptr;
                    string_buf_write_idx += str.len;

                    operations.append(.{
                        .line = line_num,
                        .operation = .{
                            .opcode = .PrintStr,
                            .data = .{
                                .first_operand = .{ .str_ptr = str_ptr },
                                .second_operand = .{ .str_len = str.len },
                                .third_operand = .{ .unused = {} },
                            },
                        },
                    }) catch unreachable;
                } else {
                    operations.append(.{
                        .line = line_num,
                        .operation = .{
                            .opcode = .PrintVar,
                            .data = .{
                                .first_operand = .{ .operand = get_operand_pointer(cleaned_line[start_print..]) },
                                .second_operand = .{ .unused = {} },
                                .third_operand = .{ .unused = {} },
                            },
                        },
                    }) catch unreachable;
                }
            },
            .PrintLn,
            => {
                const start_print = number_length + 1 + first_token_length + 1;
                if (cleaned_line[start_print] == '"') {

                    // this is somewhat subtle, line could be longer than 64 bytes so we look at the whole buffer and update line length accordingly
                    const end_print = start_print + 1 + std.mem.indexOfScalar(u8, io_buf[it..][start_print + 1 ..], '"').?;
                    line_length = end_print + 1;

                    // copy strings to separate buffer, io_buf will be overwritten
                    const str = io_buf[it..][start_print + 1 .. end_print];
                    @memcpy(string_buf[string_buf_write_idx..][0..str.len], str);
                    const str_ptr = string_buf[string_buf_write_idx..].ptr;
                    string_buf_write_idx += str.len;

                    operations.append(ParsedOperation{
                        .line = line_num,
                        .operation = .{
                            .opcode = .PrintLnStr,
                            .data = .{
                                .first_operand = .{ .str_ptr = str_ptr },
                                .second_operand = .{ .str_len = str.len },
                                .third_operand = .{ .unused = {} },
                            },
                        },
                    }) catch unreachable;
                } else {
                    operations.append(ParsedOperation{
                        .line = line_num,
                        .operation = .{
                            .opcode = .PrintLnVar,
                            .data = .{
                                .first_operand = .{ .operand = get_operand_pointer(cleaned_line[start_print..]) },
                                .second_operand = .{ .unused = {} },
                                .third_operand = .{ .unused = {} },
                            },
                        },
                    }) catch unreachable;
                }
            },
        }

        it += line_length + 1;
    }
    const t3 = std.time.Instant.now() catch unreachable;

    std.mem.sortUnstable(ParsedOperation, operations.items, void{}, ParsedOperation.cmp);

    var line_map = std.AutoArrayHashMap(u32, u32).init(allocator);
    defer line_map.deinit();

    for (operations.items, 0..) |operation, i| {
        line_map.put(operation.line, @intCast(i)) catch unreachable;
        ops[i] = operation.operation;
    }
    ops[operations.items.len].opcode = .Exit;

    for (0..operations.items.len) |i| {
        switch (ops[i].opcode) {
            .BranchEq,
            .BranchNe,
            .BranchLe,
            .BranchLq,
            .BranchGr,
            .BranchGq,
            => {
                ops[i].data.third_operand.next_instruction = @intCast(line_map.get(@intCast(ops[i].data.third_operand.next_instruction)).?);
            },
            else => {},
        }
    }
    const t4 = std.time.Instant.now() catch unreachable;

    funcFromOpcode(ops[0].opcode)(0);
    const t5 = std.time.Instant.now() catch unreachable;

    _ = stdout.write(fbstream.getWritten()) catch unreachable;

    const t6 = std.time.Instant.now() catch unreachable;

    const reading = t2.since(t1);
    std.debug.print("reading input program took: {}\n", .{std.fmt.fmtDuration(reading)}); // 0.000007s on kattis
    const parsing = t3.since(t2);
    std.debug.print("parsing input program took: {}\n", .{std.fmt.fmtDuration(parsing)}); // 0.0003s on kattis
    const fixing = t4.since(t3);
    std.debug.print("fixing line numbers took: {}\n", .{std.fmt.fmtDuration(fixing)}); // 0.0002s on kattis
    const running = t5.since(t4);
    std.debug.print("running program took: {}\n", .{std.fmt.fmtDuration(running)}); // 0.0029s on kattis
    const writing = t6.since(t5);
    std.debug.print("writing output took: {}\n", .{std.fmt.fmtDuration(writing)}); // 0.000006s on kattis
    const total = t6.since(t1);
    std.debug.print("total: {}\n", .{std.fmt.fmtDuration(total)});
}
// prime bench results on my machine:
// reading input program took: 3.886us
// parsing input program took: 39.734us
// fixing line numbers took: 10.176us
// running program took: 396.136us
// writing output took: 35.21us
// total: 485.142us
