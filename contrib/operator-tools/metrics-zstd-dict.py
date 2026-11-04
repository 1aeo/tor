#!/usr/bin/env python3
# Copyright (c) 2026, The Tor Project, Inc.
# See LICENSE for licensing information.

"""Print every MetricsPort line, with the sample value removed.

Tor's prometheus output only includes series that apply to the running
process. Relay counters are still emitted when their value is zero, so a
normal relay scrape already contains every tor_relay_* series except
tor_relay_signing_cert_expiry_timestamp (only present when OfflineMasterKey
is set and a signing cert is loaded). A process that is not hosting an
onion service never emits tor_hs_* lines. This program reads the metric
tables in the Tor sources and prints the lines those code paths would emit,
in the same format as:

    curl -s 127.0.0.1:9035/metrics | sed 's/ [0-9]*$//'

The result is a raw zstd dictionary (not the output of "zstd --train"):

    zstd -D metrics-zstd.dict scrape.prom

Family order in a live scrape follows the metrics hash table and changes
when the process restarts (the siphash key is random). Lines that share a
metric name stay together, in the order Tor inserts them. This dictionary
keeps that within-family order. Pass the same --onion and --port values the
relay is configured with so those label bytes are in the dictionary too.

DNS "record" labels (A / PTR / AAAA) are compiled out of Tor until libevent
is fixed (#40490) and are not included.
"""

import argparse
import difflib
import re
import sys
from pathlib import Path


PLACEHOLDER_ONION = "a" * 56
DEFAULT_PORT = 80

# Files that are allowed to call metrics_store_add() outside the unit tests.
# A new file here means a new metrics source this generator must learn.
METRICS_ADD_FILES = {
    "src/feature/relay/relay_metrics.c",
    "src/feature/hs/hs_metrics.c",
    "src/lib/log/log_sys.c",
}

# Subsystems that publish a metrics store. MetricsPort walks these in
# subsystem_list.c order (logging, then relay, then hs).
METRICS_GET_FILES = [
    "src/lib/log/log_sys.c",
    "src/feature/relay/relay_sys.c",
    "src/feature/hs/hs_sys.c",
]


class CheckFailure(Exception):
    """The sources and the generator disagree."""


def die(msg):
    """Raise CheckFailure."""
    raise CheckFailure(msg)


def repo_root():
    """Return the tor repository root (two levels above this script)."""
    return Path(__file__).resolve().parents[2]


def read_text(path):
    """Read a source file as UTF-8 text."""
    return Path(path).read_text(encoding="utf-8")


def strip_comments(src):
    """Remove C comments, preserving newlines so line-oriented scans still work."""
    out = []
    i = 0
    n = len(src)
    while i < n:
        if src.startswith("/*", i):
            end = src.find("*/", i + 2)
            if end < 0:
                die("unclosed block comment")
            out.append("\n" * src.count("\n", i, end))
            i = end + 2
            continue
        if src.startswith("//", i):
            end = src.find("\n", i)
            if end < 0:
                break
            i = end
            continue
        if src[i] == '"':
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == '"':
                    j += 1
                    break
                j += 1
            out.append(src[i:j])
            i = j
            continue
        out.append(src[i])
        i += 1
    return "".join(out)


def strip_if0(src):
    """Drop #if 0 regions. Refuse #else/#elif, which this stripper does not fold."""
    lines = src.splitlines(keepends=True)
    out = []
    skip_depth = 0
    if_re = re.compile(r"#\s*if(?:n?def)?\b")
    for line in lines:
        stripped = line.lstrip()
        if skip_depth:
            if if_re.match(stripped):
                skip_depth += 1
            elif re.match(r"#\s*endif\b", stripped):
                skip_depth -= 1
            elif skip_depth == 1 and re.match(r"#\s*(?:else|elif)\b", stripped):
                die("else/elif inside #if 0; update the preprocessor stripper")
            continue
        if re.match(r"#\s*if\s+0\b", stripped):
            skip_depth = 1
            continue
        out.append(line)
    if skip_depth:
        die("unclosed #if 0")
    return "".join(out)


def preprocess(src):
    """Comment-strip and drop #if 0 blocks."""
    return strip_if0(strip_comments(src))


def match_brace(src, open_index):
    """Return (body, index_after_close) for the brace at open_index."""
    if src[open_index] != "{":
        die("expected '{'")
    depth = 0
    i = open_index
    n = len(src)
    while i < n:
        c = src[i]
        if c == '"' or c == "'":
            q = c
            i += 1
            while i < n:
                if src[i] == "\\":
                    i += 2
                    continue
                if src[i] == q:
                    i += 1
                    break
                i += 1
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return src[open_index + 1:i], i + 1
        i += 1
    die("unbalanced brace")


def extract_functions(src):
    """Map function name to body for top-level C definitions in src."""
    pattern = re.compile(
        r"(?:^|\n)(?:static\s+)?(?:inline\s+)?(?:const\s+)?"
        r"(?:char\s*\*\s*|void\s+|int\s+|bool\s+|"
        r"smartlist_t\s*\*\s*|buf_t\s*\*\s*)(\w+)\s*\("
    )
    funcs = {}
    for match in pattern.finditer(src):
        name = match.group(1)
        paren = match.end() - 1
        if src[paren] != "(":
            continue
        _args, after_paren = split_paren(src, paren)
        j = after_paren
        while j < len(src) and src[j] in " \t\r\n":
            j += 1
        if j >= len(src) or src[j] != "{":
            continue
        body, _end = match_brace(src, j)
        funcs[name] = body
    return funcs


def split_paren(src, open_index):
    """Return (inner, index_after_close) for the parenthesis at open_index."""
    if src[open_index] != "(":
        die("expected '('")
    depth = 0
    i = open_index
    n = len(src)
    start = open_index + 1
    while i < n:
        c = src[i]
        if c == '"' or c == "'":
            q = c
            i += 1
            while i < n:
                if src[i] == "\\":
                    i += 2
                    continue
                if src[i] == q:
                    i += 1
                    break
                i += 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return src[start:i], i + 1
        i += 1
    die("unbalanced parenthesis")


def split_top_level_commas(text):
    """Split text on commas that are not inside parentheses or strings."""
    parts = []
    buf = []
    depth = 0
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == '"' or c == "'":
            q = c
            buf.append(c)
            i += 1
            while i < n:
                buf.append(text[i])
                if text[i] == "\\":
                    i += 1
                    if i < n:
                        buf.append(text[i])
                    i += 1
                    continue
                if text[i] == q:
                    i += 1
                    break
                i += 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        if c == "," and depth == 0:
            parts.append("".join(buf).strip())
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts


def find_calls(body, name):
    """Yield (start, arg_list) for each call to name in body."""
    i = 0
    while True:
        j = body.find(name, i)
        if j < 0:
            return
        if j > 0 and (body[j - 1].isalnum() or body[j - 1] == "_"):
            i = j + 1
            continue
        k = j + len(name)
        if k < len(body) and (body[k].isalnum() or body[k] == "_"):
            i = j + 1
            continue
        while k < len(body) and body[k].isspace():
            k += 1
        if k >= len(body) or body[k] != "(":
            i = j + 1
            continue
        inner, end = split_paren(body, k)
        yield j, split_top_level_commas(inner)
        i = end


def unquote(arg):
    """Return the contents of a simple C string literal, or None."""
    text = arg.strip()
    if len(text) < 2 or text[0] != '"' or text[-1] != '"':
        return None
    inner = text[1:-1]
    if "\\" in inner or '"' in inner:
        die("unsupported escape in C string %s" % text)
    return inner


def parse_switch_returns(body):
    """Map `case NAME:` labels to the string literal they return."""
    result = {}
    parts = re.split(r"\bcase\s+", body)
    for part in parts[1:]:
        match = re.match(r"(\w+)\s*:", part)
        if not match:
            continue
        ret = re.search(r'return\s+"([^"]*)"\s*;', part)
        if ret:
            result[match.group(1)] = ret.group(1)
    return result


def c_int_defines(text, name_re):
    """Map matching #define names to integer values (decimal or hex)."""
    found = {}
    for match in re.finditer(
            r"#define\s+(" + name_re + r")\s+(0x[0-9A-Fa-f]+|\d+)", text):
        found[match.group(1)] = int(match.group(2), 0)
    return found


def initializer_entries(src, decl_re):
    """Return the brace bodies of entries in a static array initializer."""
    match = re.search(decl_re, src)
    if not match:
        die("could not find %s" % decl_re)
    brace = src.find("{", match.end() - 1)
    body, _end = match_brace(src, brace)
    entries = []
    j = 0
    while True:
        k = body.find("{", j)
        if k < 0:
            break
        entry, nxt = match_brace(body, k)
        entries.append(entry)
        j = nxt
    return entries


def field_token(entry, field):
    """Return the identifier assigned to .field, or None."""
    match = re.search(r"\.%s\s*=\s*(\w+)" % field, entry)
    return match.group(1) if match else None


def field_string(entry, field):
    """Return the C string assigned to .field, or None."""
    match = re.search(r'\.%s\s*=\s*"([^"]*)"' % field, entry)
    return match.group(1) if match else None


def metric_name_from_entry(entry):
    """Return the prometheus name from a .name = METRICS_NAME(...) field."""
    match = re.search(r"\.name\s*=\s*METRICS_NAME\((\w+)\)", entry)
    if not match:
        die("metrics entry has no METRICS_NAME")
    return "tor_" + match.group(1)


def render_label(key, value):
    """Format one prometheus label the way metrics_format_label() does."""
    if any(ch in value for ch in '"\\\n'):
        die("label value is not emitted verbatim by Tor: %s=%s" % (key, value))
    rendered = '%s="%s"' % (key, value)
    # metrics_format_label() writes into a 128-byte stack buffer.
    if len(rendered) >= 128:
        die("label does not fit in metrics_format_label buffer: %s" % rendered)
    return rendered


def render_family(name, mtype, help_text, samples, buckets=None):
    """Render one prometheus family with values omitted."""
    if "\n" in help_text:
        die("help text contains a newline")
    lines = [
        "# HELP %s %s" % (name, help_text),
        "# TYPE %s %s" % (name, mtype),
    ]
    if mtype == "histogram":
        if not buckets:
            die("histogram %s has no buckets" % name)
        for labels in samples:
            lab = ",".join(render_label(k, v) for k, v in labels)
            for bucket in buckets:
                le = "%.2f" % float(bucket)
                if lab:
                    lines.append('%s_bucket{%s,le="%s"}' % (name, lab, le))
                else:
                    lines.append('%s_bucket{le="%s"}' % (name, le))
            if lab:
                lines.append('%s_bucket{%s,le="+Inf"}' % (name, lab))
                lines.append("%s_sum{%s}" % (name, lab))
                lines.append("%s_count{%s}" % (name, lab))
            else:
                lines.append('%s_bucket{le="+Inf"}' % (name,))
                lines.append("%s_sum" % name)
                lines.append("%s_count" % name)
    else:
        for labels in samples:
            if labels:
                lab = ",".join(render_label(k, v) for k, v in labels)
                lines.append("%s{%s}" % (name, lab))
            else:
                lines.append(name)
    return lines


def load_sources(root):
    """Read and preprocess the C files that define MetricsPort output."""
    rels = [
        "src/feature/relay/relay_metrics.c",
        "src/feature/hs/hs_metrics.c",
        "src/feature/hs/hs_metrics_entry.c",
        "src/feature/hs/hs_metrics_entry.h",
        "src/lib/log/log_sys.c",
        "src/lib/metrics/prometheus.c",
        "src/lib/metrics/metrics_common.c",
        "src/lib/metrics/metrics_common.h",
        "src/core/mainloop/connection.c",
        "src/core/mainloop/connection.h",
        "src/core/or/relay.c",
        "src/core/or/or.h",
        "src/app/main/subsystem_list.c",
        "src/feature/metrics/metrics.c",
    ]
    sources = {}
    for rel in rels:
        path = root / rel
        if not path.is_file():
            die("missing %s" % path)
        sources[rel] = preprocess(read_text(path))
    return sources


def type_strings(sources):
    """Map METRICS_TYPE_* enumerators to the prometheus type word."""
    funcs = extract_functions(sources["src/lib/metrics/metrics_common.c"])
    body = funcs.get("metrics_type_to_str")
    if body is None:
        die("metrics_type_to_str() not found")
    return parse_switch_returns(body)


def assert_formatter_contract(sources):
    """Fail if prometheus.c no longer prints the format this script reproduces."""
    text = sources["src/lib/metrics/prometheus.c"]
    # These are the printf formats as they appear in prometheus.c, including
    # the C backslash escapes. A change here means the dictionary layout drifted.
    fragments = [
        r'# HELP %s %s\n',
        r'# TYPE %s %s\n',
        r'%s{%s} %" PRIi64 "\n',
        r'%s %" PRIi64 "\n',
        r'%s_bucket{%s,le=\"%.2f\"} %" PRIi64 "\n',
        r'%s_bucket{le=\"%.2f\"} %" PRIi64 "\n',
        r'%s_bucket{%s,le=\"+Inf\"} %" PRIi64 "\n',
        r'%s_bucket{le=\"+Inf\"} %" PRIi64 "\n',
        r'%s_sum{%s} %" PRIi64 "\n',
        r'%s_sum %" PRIi64 "\n',
        r'%s_count{%s} %" PRIi64 "\n',
        r'%s_count %" PRIi64 "\n',
        'smartlist_join_strings(labels, ",", 0, NULL)',
    ]
    for fragment in fragments:
        if fragment not in text:
            die("prometheus format changed, missing fragment: %s" % fragment)
    header = sources["src/lib/metrics/metrics_common.h"]
    if not re.search(
            r"#define\s+METRICS_NAME\(name\)\s+METRICS_STR\(tor_\s*##\s*name\)",
            header):
        die("METRICS_NAME() no longer prefixes tor_")
    subs = sources["src/app/main/subsystem_list.c"]
    order = [subs.index("&" + name) for name in (
        "sys_logging", "sys_relay", "sys_hs")]
    if order != sorted(order):
        die("subsystem order is no longer logging, relay, hs")
    metrics_c = sources["src/feature/metrics/metrics.c"]
    if "tor_subsystems[i]" not in metrics_c or "sys->get_metrics" not in metrics_c:
        die("metrics_get_output() no longer walks subsystems in list order")


def connection_types(sources):
    """Return connection-type display strings in the order the fill loops use.

    The numeric range and the `i == 10` skip are read from the C code.
    """
    header = sources["src/core/mainloop/connection.h"]
    defines = c_int_defines(header, r"CONN_TYPE_\w+")
    if "CONN_TYPE_MIN_" not in defines or "CONN_TYPE_MAX_" not in defines:
        die("CONN_TYPE_MIN_/MAX_ not found")
    by_num = {}
    for name, num in defines.items():
        if name in ("CONN_TYPE_MIN_", "CONN_TYPE_MAX_"):
            continue
        if num in by_num:
            die("duplicate connection type number %s" % num)
        by_num[num] = name
    funcs = extract_functions(sources["src/core/mainloop/connection.c"])
    strings = parse_switch_returns(funcs["conn_type_to_string"])
    return by_num, strings, defines["CONN_TYPE_MIN_"], defines["CONN_TYPE_MAX_"]


def types_for_conn_loop(body, by_num, strings, lo, hi):
    """Connection type strings visited by one fill_conn_* loop."""
    if not re.search(r"CONN_TYPE_MIN_\s*;\s*i\s*<\s*CONN_TYPE_MAX_", body):
        die("connection fill loop bounds changed")
    skips = {int(n) for n in re.findall(r"if\s*\(\s*i\s*==\s*(\d+)\s*\)", body)}
    if not skips:
        die("connection fill loop no longer skips the unused type")
    ordered = []
    for num in range(lo, hi):
        if num in skips:
            continue
        name = by_num.get(num)
        if name is None:
            die("connection type %s has no CONN_TYPE_* name" % num)
        if name not in strings:
            die("conn_type_to_string() has no string for %s" % name)
        ordered.append(strings[name])
    return ordered


def address_families(sources):
    """Map AF_* tokens to the family label, from af_to_string()."""
    funcs = extract_functions(sources["src/feature/relay/relay_metrics.c"])
    return parse_switch_returns(funcs["af_to_string"])


def handshake_names(sources):
    """Handshake label strings for t in 0..MAX_ONION_HANDSHAKE_TYPE."""
    defines = c_int_defines(
        sources["src/core/or/or.h"],
        r"ONION_HANDSHAKE_TYPE_\w+|MAX_ONION_HANDSHAKE_TYPE")
    if "MAX_ONION_HANDSHAKE_TYPE" not in defines:
        die("MAX_ONION_HANDSHAKE_TYPE not found")
    by_val = {}
    for name, val in defines.items():
        if name == "MAX_ONION_HANDSHAKE_TYPE":
            continue
        if val in by_val:
            die("duplicate handshake type value %s" % val)
        by_val[val] = name
    funcs = extract_functions(sources["src/feature/relay/relay_metrics.c"])
    strings = parse_switch_returns(funcs["handshake_type_to_str"])
    ordered = []
    for val in range(0, defines["MAX_ONION_HANDSHAKE_TYPE"] + 1):
        name = by_val.get(val)
        if name is None or name not in strings:
            die("no handshake string for type %s" % val)
        ordered.append(strings[name])
    return ordered


def relay_commands(sources):
    """Map RELAY_COMMAND_* enumerators to relay_command_to_string() text."""
    funcs = extract_functions(sources["src/core/or/relay.c"])
    if "relay_command_to_string" not in funcs:
        die("relay_command_to_string() not found")
    return parse_switch_returns(funcs["relay_command_to_string"])


def samples_from_connections(body, ctx):
    """Label sets for fill_conn_counter_values / fill_conn_gauge_values."""
    helper = ctx["funcs"]["fill_single_connection_value"]
    pairs = []
    for _start, args in find_calls(helper, "metrics_format_label"):
        if len(args) != 2:
            die("unexpected metrics_format_label arity")
        key = unquote(args[0])
        if key is None:
            die("connection label key is not a string")
        pairs.append((key, args[1].strip()))
    calls = re.findall(
        r'fill_single_connection_value\s*\(\s*'
        r'sentry\s*,\s*i\s*,\s*"([^"]*)"\s*,\s*"([^"]*)"\s*,\s*(AF_\w+)',
        body)
    if not calls:
        die("no fill_single_connection_value() calls found")
    types = types_for_conn_loop(
        body, ctx["conn_by_num"], ctx["conn_strings"],
        ctx["conn_lo"], ctx["conn_hi"])
    samples = []
    for type_str in types:
        for direction, state, af_token in calls:
            if af_token not in ctx["af_map"]:
                die("no family string for %s" % af_token)
            # Longest marker first so "state" cannot match inside a longer call.
            values = [
                ("conn_type_to_string", type_str),
                ("af_to_string", ctx["af_map"][af_token]),
                ("direction", direction),
                ("state", state),
            ]
            labels = []
            for key, expr in pairs:
                matched = None
                for marker, value in values:
                    if marker in expr:
                        matched = value
                        break
                if matched is None:
                    die("unrecognized connection label expression %s" % expr)
                labels.append((key, matched))
            samples.append(labels)
    return samples


def samples_from_streams(body, ctx):
    """Label sets for fill_streams_values()."""
    helper = ctx["funcs"]["fill_single_stream_value"]
    calls_fmt = list(find_calls(helper, "metrics_format_label"))
    if len(calls_fmt) != 1:
        die("stream metric label shape changed")
    key = unquote(calls_fmt[0][1][0])
    if key is None or "relay_command_to_string" not in calls_fmt[0][1][1]:
        die("stream metric no longer labels relay_command_to_string()")
    commands = re.findall(
        r"fill_single_stream_value\s*\(\s*sentry\s*,\s*(RELAY_COMMAND_\w+)\s*\)",
        body)
    if not commands:
        die("no stream commands found")
    samples = []
    for command in commands:
        if command not in ctx["commands"]:
            die("relay_command_to_string() has no string for %s" % command)
        samples.append([(key, ctx["commands"][command])])
    return samples


def samples_from_onionskins(body, ctx):
    """Label sets for fill_onionskins_values()."""
    if not re.search(
            r"for\s*\([^;]*;\s*t\s*<=\s*MAX_ONION_HANDSHAKE_TYPE\s*;", body):
        die("onionskin loop no longer walks 0..MAX_ONION_HANDSHAKE_TYPE")
    actions = []
    saw_type = False
    for _start, args in find_calls(body, "metrics_format_label"):
        key = unquote(args[0])
        val = unquote(args[1])
        if key == "type":
            saw_type = True
            if val is not None:
                die("onionskin type label became a literal")
        elif key == "action" and val is not None:
            actions.append(val)
        else:
            die("unexpected onionskin label %s" % args)
    if not saw_type or not actions:
        die("onionskin labels not found")
    # type_label is created once per handshake and applied before each action.
    samples = []
    for handshake in ctx["handshakes"]:
        for action in actions:
            samples.append([("type", handshake), ("action", action)])
    return samples


def samples_from_name_table(body):
    """Label sets for a fill function that loops over a .name table."""
    arrays = re.findall(r"(\w+)\s*\[\s*\]\s*=\s*\{", body)
    if len(arrays) != 1:
        die("expected one name table, found %s" % (arrays,))
    labels = list(find_calls(body, "metrics_format_label"))
    if len(labels) != 1:
        die("name-table metric has %d labels; update the generator" % len(labels))
    args = labels[0][1]
    key = unquote(args[0])
    if key is None or unquote(args[1]) is not None:
        die("name-table label is not a single dynamic value")
    adds = list(find_calls(body, "metrics_store_add"))
    if len(adds) != 1:
        die("name-table fill function has %d metrics_store_add calls" % len(adds))
    values = re.findall(r'\.name\s*=\s*"([^"]*)"', body)
    if not values:
        die("name table is empty")
    return [[(key, value)] for value in values]


def samples_from_literals(body):
    """Label sets for a fill function whose labels are all string literals."""
    events = []
    for start, _args in find_calls(body, "metrics_store_add"):
        events.append((start, "add"))
    label_events = []
    for start, args in find_calls(body, "metrics_format_label"):
        if len(args) != 2:
            die("unexpected metrics_format_label arity")
        key = unquote(args[0])
        val = unquote(args[1])
        if key is None or val is None:
            die("literal fill function grew a dynamic label: %s" % args)
        label_events.append((start, key, val))
        events.append((start, "label"))
    if not any(kind == "add" for _start, kind in events):
        die("fill function does not call metrics_store_add()")
    n_add_label = len(list(find_calls(body, "metrics_store_entry_add_label")))
    if n_add_label != len(label_events):
        die("a label is passed through a variable; update the generator")
    events.sort()
    samples = []
    current = None
    label_i = 0
    for _start, kind in events:
        if kind == "add":
            if current is not None:
                samples.append(current)
            current = []
        else:
            if current is None:
                die("label appears before metrics_store_add()")
            _s, key, val = label_events[label_i]
            label_i += 1
            current.append((key, val))
    if current is not None:
        samples.append(current)
    return samples


def samples_for_body(name, body, ctx):
    """Dispatch a relay fill function to the matching sample builder."""
    if "fill_single_connection_value" in body:
        return samples_from_connections(body, ctx)
    if "fill_single_stream_value" in body:
        return samples_from_streams(body, ctx)
    if "handshake_type_to_str" in body:
        return samples_from_onionskins(body, ctx)
    dynamic = False
    n_labels = 0
    for _start, args in find_calls(body, "metrics_format_label"):
        n_labels += 1
        if unquote(args[1]) is None:
            dynamic = True
    if dynamic and re.search(r'\.name\s*=\s*"', body):
        return samples_from_name_table(body)
    if dynamic:
        die("%s has a dynamic label this generator does not understand" % name)
    return samples_from_literals(body)


def bucket_tables(text):
    """Map int64_t bucket-array names to their bucket edges."""
    tables = {}
    for match in re.finditer(
            r"(?:static\s+)?const\s+int64_t\s+(\w+)\s*\[\s*\]\s*=\s*\{([^}]*)\}",
            text):
        nums = re.findall(r"(?<![\w.])(\d+)(?![\w.])", match.group(2))
        if not nums:
            die("empty bucket table %s" % match.group(1))
        tables[match.group(1)] = [int(n) for n in nums]
    return tables


def relay_lines(sources, ctx, include_signing):
    """Prometheus lines for every relay metric family."""
    entries = initializer_entries(
        sources["src/feature/relay/relay_metrics.c"],
        r"relay_metrics_entry_t\s+base_metrics\s*\[\s*\]\s*=")
    if not entries:
        die("no relay base_metrics entries")
    lines = []
    for entry in entries:
        name = metric_name_from_entry(entry)
        if not include_signing and "signing_cert_expiry" in name:
            continue
        mtype_tok = field_token(entry, "type")
        help_text = field_string(entry, "help")
        fill = field_token(entry, "fill_fn")
        if mtype_tok not in ctx["types"] or help_text is None or fill is None:
            die("incomplete relay metric entry for %s" % name)
        if fill not in ctx["funcs"]:
            die("fill function %s not found" % fill)
        if ctx["types"][mtype_tok] == "histogram":
            die("relay histogram %s needs bucket support" % name)
        samples = samples_for_body(fill, ctx["funcs"][fill], ctx)
        lines.extend(render_family(
            name, ctx["types"][mtype_tok], help_text, samples))
    return lines


def hs_reason_tables(sources):
    """Map HS_METRICS_* keys to the reason-label strings they emit."""
    header = sources["src/feature/hs/hs_metrics_entry.h"]
    defines = dict(re.findall(
        r'#define\s+(HS_METRICS_ERR_\w+)\s+"([^"]*)"', header))
    if not defines:
        die("no HS metrics error reasons found")
    arrays = {}
    for match in re.finditer(
            r"const\s+char\s*\*\s*(hs_metrics_\w+)\s*\[\s*\]\s*=\s*\{([^}]*)\}",
            sources["src/feature/hs/hs_metrics_entry.c"]):
        idents = re.findall(r"HS_METRICS_ERR_\w+", match.group(2))
        arrays[match.group(1)] = [defines[ident] for ident in idents]
    key_to_reasons = {}
    for match in re.finditer(
            r"case\s+(HS_METRICS_\w+)\s*:\s*error_reasons\s*=\s*(hs_metrics_\w+)\s*;",
            sources["src/feature/hs/hs_metrics.c"]):
        key_to_reasons[match.group(1)] = arrays[match.group(2)]
    return key_to_reasons


def hs_label_keys(sources):
    """Return (normal_keys, error_keys) in metrics_format_label() call order."""
    funcs = extract_functions(sources["src/feature/hs/hs_metrics.c"])
    body = funcs.get("add_metric_with_labels")
    if body is None:
        die("add_metric_with_labels() not found")
    split = re.search(
        r"for\s*\(\s*size_t\s+i\s*=\s*0\s*;\s*i\s*<\s*num_error_reasons",
        body)
    if not split:
        die("HS error-label loop not found")
    def keys_in(chunk):
        found = []
        for _start, args in find_calls(chunk, "metrics_format_label"):
            key = unquote(args[0])
            if key is None:
                die("HS label key is not a string")
            found.append(key)
        return found
    normal = keys_in(body[:split.start()])
    error = keys_in(body[split.start():])
    if not normal or not error:
        die("could not recover HS label order")
    return normal, error


def hs_lines(sources, ctx, onions, ports):
    """Prometheus lines for one store per onion service."""
    entries = initializer_entries(
        sources["src/feature/hs/hs_metrics_entry.c"],
        r"hs_metrics_entry_t\s+base_metrics\s*\[\s*\]\s*=")
    reasons_for = hs_reason_tables(sources)
    normal_keys, error_keys = hs_label_keys(sources)
    buckets_for = bucket_tables(sources["src/feature/hs/hs_metrics_entry.c"])
    lines = []
    for onion in onions:
        for entry in entries:
            name = metric_name_from_entry(entry)
            mtype_tok = field_token(entry, "type")
            help_text = field_string(entry, "help")
            key = field_token(entry, "key")
            if mtype_tok not in ctx["types"] or help_text is None or key is None:
                die("incomplete HS metric entry for %s" % name)
            mtype = ctx["types"][mtype_tok]
            port_label = bool(re.search(r"\.port_as_label\s*=\s*true\b", entry))
            reasons = reasons_for.get(key)
            label_keys = error_keys if reasons else normal_keys
            port_iter = list(ports) if port_label else [None]
            reason_iter = reasons if reasons else [None]
            samples = []
            for port in port_iter:
                for reason in reason_iter:
                    labels = []
                    for label_key in label_keys:
                        if label_key == "onion":
                            labels.append(("onion", onion))
                        elif label_key == "reason":
                            if reason is None:
                                continue
                            labels.append(("reason", reason))
                        elif label_key == "port":
                            if port is None:
                                continue
                            labels.append(("port", str(port)))
                        else:
                            die("unexpected HS label %s" % label_key)
                    samples.append(labels)
            buckets = None
            if mtype == "histogram":
                bucket_name = field_token(entry, "buckets")
                if bucket_name not in buckets_for:
                    die("no buckets for histogram %s" % name)
                buckets = buckets_for[bucket_name]
            lines.extend(render_family(
                name, mtype, help_text, samples, buckets))
    return lines


def logging_lines(sources, ctx):
    """Prometheus lines for the logging subsystem (tor_bug_reached_count)."""
    funcs = extract_functions(sources["src/lib/log/log_sys.c"])
    body = funcs.get("logging_metrics_get_stores")
    if body is None:
        die("logging_metrics_get_stores() not found")
    match = re.search(
        r"metrics_store_add\s*\(\s*the_store\s*,\s*(METRICS_TYPE_\w+)\s*,\s*"
        r'METRICS_NAME\((\w+)\)\s*,\s*"([^"]*)"',
        body)
    if not match:
        die("could not parse the logging metric")
    mtype = ctx["types"][match.group(1)]
    name = "tor_" + match.group(2)
    help_text = match.group(3)
    samples = samples_for_body("logging_metrics_get_stores", body, ctx)
    return render_family(name, mtype, help_text, samples)


def build_context(sources):
    """Parse the shared tables the fill functions index into."""
    assert_formatter_contract(sources)
    by_num, strings, lo, hi = connection_types(sources)
    funcs = extract_functions(sources["src/feature/relay/relay_metrics.c"])
    return {
        "types": type_strings(sources),
        "funcs": funcs,
        "conn_by_num": by_num,
        "conn_strings": strings,
        "conn_lo": lo,
        "conn_hi": hi,
        "af_map": address_families(sources),
        "handshakes": handshake_names(sources),
        "commands": relay_commands(sources),
    }


def generate(root, onions, ports, include_signing=True, include_hs=True):
    """Return the dictionary lines for this Tor tree."""
    sources = load_sources(root)
    ctx = build_context(sources)
    lines = []
    lines.extend(logging_lines(sources, ctx))
    lines.extend(relay_lines(sources, ctx, include_signing))
    if include_hs:
        lines.extend(hs_lines(sources, ctx, onions, ports))
    return lines


def render(lines):
    """Join dictionary lines the way the MetricsPort ends records."""
    return "\n".join(lines) + "\n"


def sed_strip(line):
    """Apply the operator's `sed 's/ [0-9]*$//'` substitution."""
    return re.sub(r" [0-9]*$", "", line)


def source_metric_names(root):
    """Every METRICS_NAME() use under src/, excluding unit tests and the macro."""
    names = []
    src = root / "src"
    for path in list(src.rglob("*.c")) + list(src.rglob("*.h")):
        if "test" in path.parts:
            continue
        text = strip_comments(read_text(path))
        for line in text.splitlines():
            if line.lstrip().startswith("#define"):
                continue
            for match in re.finditer(r"\bMETRICS_NAME\((\w+)\)", line):
                names.append("tor_" + match.group(1))
    if len(names) != len(set(names)):
        die("duplicate METRICS_NAME() in sources")
    return names


def literal_labels(src):
    """Yield key, value for metrics_format_label(\"key\", \"value\") calls."""
    body = preprocess(src)
    for _start, args in find_calls(body, "metrics_format_label"):
        key = unquote(args[0])
        val = unquote(args[1]) if len(args) > 1 else None
        if key is not None and val is not None:
            yield key, val


def assert_source_coverage(root, text):
    """Fail if a metric or static label in the sources is missing from text."""
    names = source_metric_names(root)
    help_names = []
    for line in text.splitlines():
        if line.startswith("# HELP "):
            help_names.append(line.split()[2])
    if sorted(help_names) != sorted(names):
        missing = sorted(set(names) - set(help_names))
        extra = sorted(set(help_names) - set(names))
        die("metric name mismatch missing=%s extra=%s" % (missing, extra))

    relay = read_text(root / "src/feature/relay/relay_metrics.c")
    for key, val in literal_labels(relay):
        rendered = '%s="%s"' % (key, val)
        if rendered not in text:
            die("static label missing from dictionary: %s" % rendered)

    header = read_text(root / "src/feature/hs/hs_metrics_entry.h")
    for value in re.findall(r'#define\s+HS_METRICS_ERR_\w+\s+"([^"]*)"', header):
        if 'reason="%s"' % value not in text:
            die("HS reason label missing: %s" % value)

    add_files = []
    get_files = []
    for path in (root / "src").rglob("*.c"):
        if "test" in path.parts:
            continue
        rel = str(path.relative_to(root))
        raw = read_text(path)
        # Indented calls only. The definition in metrics_store.c is at column 0.
        if re.search(r"(?m)^[ \t]+.*\bmetrics_store_add\s*\(", raw):
            add_files.append(rel)
        if re.search(r"\.get_metrics\s*=", raw):
            get_files.append(rel)
    if set(add_files) != METRICS_ADD_FILES:
        die("metrics_store_add() call sites changed: %s" % sorted(add_files))
    if set(get_files) != set(METRICS_GET_FILES):
        die("get_metrics assignments changed: %s (expected %s)" % (
            sorted(get_files), METRICS_GET_FILES))


def assert_golden(text):
    """Fail if a few fully rendered lines do not match the C label order."""
    onion = PLACEHOLDER_ONION
    required = [
        "# HELP tor_bug_reached_count Total number of BUG() and similar assertion reached",
        "# TYPE tor_bug_reached_count counter",
        "tor_bug_reached_count",
        "tor_relay_load_socket_total{state=\"opened\"}",
        "tor_relay_load_socket_total",
        "tor_relay_load_global_rate_limit_reached_total{side=\"read\"}",
        "tor_relay_load_global_rate_limit_reached_total{side=\"write\"}",
        "tor_relay_traffic_bytes{direction=\"written\"}",
        "tor_relay_load_oom_bytes_total{subsys=\"hsdir\"}",
        "tor_relay_flag{type=\"HSDir\"}",
        "tor_relay_circuits_total{state=\"opened\"}",
        "tor_relay_dos_total{type=\"begindir_hsdir_rejected\"}",
        "tor_relay_congestion_control_total{state=\"cc_circuits\",action=\"circs_exited_ss\"}",
        "tor_relay_congestion_control{state=\"slow_start_exit\",action=\"cwnd\"}",
        "tor_relay_exit_dns_error_total{reason=\"tor_timeout\"}",
        "tor_relay_exit_dns_query_total",
        "tor_relay_load_tcp_exhaustion_total",
        "tor_relay_intro1_total{action=\"unknown_service\"}",
        "tor_relay_est_rend_total{action=\"duplicate_cookie\"}",
        "tor_relay_streams_total{type=\"BEGIN\"}",
        "tor_relay_streams_total{type=\"BEGIN_DIR\"}",
        "tor_relay_streams_total{type=\"RESOLVE\"}",
        "tor_relay_load_onionskins_total{type=\"tap\",action=\"processed\"}",
        "tor_relay_load_onionskins_total{type=\"ntor_v3\",action=\"dropped\"}",
        'tor_relay_connections_total{type="OR listener",direction="initiated",state="created",family="ipv4"}',
        'tor_relay_connections_total{type="Transparent pf/netfilter listener",direction="initiated",state="created",family="ipv4"}',
        'tor_relay_connections_total{type="Metrics",direction="received",state="rejected",family="ipv6"}',
        'tor_relay_connections{type="Exit",direction="received",state="opened",family="ipv4"}',
        "# HELP tor_relay_signing_cert_expiry_timestamp Timestamp at which the current online keys will expire",
        "tor_relay_signing_cert_expiry_timestamp",
        "tor_hs_intro_num_total{onion=\"%s\"}" % onion,
        "tor_hs_app_read_bytes_total{onion=\"%s\",port=\"80\"}" % onion,
        "tor_hs_app_write_bytes_total{onion=\"%s\",port=\"80\"}" % onion,
        "tor_hs_intro_rejected_intro_req_count{onion=\"%s\",reason=\"replay\"}" % onion,
        "tor_hs_rdv_error_count{onion=\"%s\",reason=\"rp_conn_failure\"}" % onion,
        "tor_hs_intro_circ_build_time_bucket{onion=\"%s\",le=\"1000.00\"}" % onion,
        "tor_hs_intro_circ_build_time_bucket{onion=\"%s\",le=\"+Inf\"}" % onion,
        "tor_hs_rend_circ_build_time_sum{onion=\"%s\"}" % onion,
        "tor_hs_rend_circ_build_time_count{onion=\"%s\"}" % onion,
        "tor_hs_pow_suggested_effort{onion=\"%s\"}" % onion,
        "# TYPE tor_hs_intro_circ_build_time histogram",
    ]
    for line in required:
        if line not in text:
            die("missing expected line: %s" % line)
    absent = ['record="', 'family="unix"', "unknown ["]
    for snippet in absent:
        if snippet in text:
            die("dictionary contains series Tor does not emit: %s" % snippet)
    first_listener = text.index(
        'tor_relay_connections_total{type="OR listener",direction="initiated",state="created",family="ipv4"}')
    first_or = text.index(
        'tor_relay_connections_total{type="OR",direction="initiated",state="created",family="ipv4"}')
    if first_listener > first_or:
        die("connection types are not emitted in CONN_TYPE order")
    tap = text.index(
        'tor_relay_load_onionskins_total{type="tap",action="processed"}')
    tap_drop = text.index(
        'tor_relay_load_onionskins_total{type="tap",action="dropped"}')
    fast = text.index(
        'tor_relay_load_onionskins_total{type="fast",action="processed"}')
    if not (tap < tap_drop < fast):
        die("onionskin label order changed")


def assert_sed_compatible(lines):
    """Every line must already look like the sed program in the module doc."""
    for line in lines:
        if line.startswith("# "):
            if sed_strip(line) != line:
                die("HELP/TYPE line would lose a trailing number: %s" % line)
        else:
            if sed_strip(line + " 0") != line or sed_strip(line + " 12345") != line:
                die("sample line is not stable under sed: %s" % line)


def validate(root, lines):
    """Run the source-coverage checks against a full default dictionary."""
    text = render(lines)
    assert_sed_compatible(lines)
    assert_source_coverage(root, text)
    assert_golden(text)
    return text


def normalize_onion(text):
    """Accept a 56-character v3 address, with or without the .onion suffix."""
    addr = text.strip().lower()
    if addr.endswith(".onion"):
        addr = addr[:-len(".onion")]
    if not re.fullmatch(r"[a-z2-7]{56}", addr):
        die("onion address must be 56 base32 characters (the y in y.onion), got %r"
            % text)
    return addr


def parse_args(argv):
    """Command line interface."""
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  %(prog)s > dict\n"
            "  %(prog)s --onion \"$(cut -d. -f1 < hs/hostname)\" "
            "--port 80 --port 443 > dict\n"
            "  zstd -D dict scrape.prom\n"
            "  %(prog)s --check\n" % {"prog": "metrics-zstd-dict.py"}
        ),
    )
    parser.add_argument(
        "--onion", action="append", default=None,
        help="v3 onion address (56 base32 chars, optional .onion suffix). "
             "Repeat for each configured service. Every --port is applied to "
             "every --onion. Default: 56 a's, a placeholder.")
    parser.add_argument(
        "--port", action="append", type=int, default=None,
        help="HiddenService virtual port. Repeatable. Default: %s. "
             "Only tor_hs_app_read_bytes_total and tor_hs_app_write_bytes_total "
             "carry a port label." % DEFAULT_PORT)
    parser.add_argument(
        "--no-hs", action="store_true",
        help="Do not emit onion-service metrics.")
    parser.add_argument(
        "--no-signing-cert", action="store_true",
        help="Omit tor_relay_signing_cert_expiry_timestamp. Tor emits it only "
             "when OfflineMasterKey is set and a signing cert is loaded.")
    parser.add_argument(
        "-o", "--output",
        help="Write to this path instead of stdout.")
    parser.add_argument(
        "--check", action="store_true",
        help="Parse the Tor sources, check the generated default dictionary, "
             "and compare it to metrics-zstd.dict next to this script.")
    parser.add_argument(
        "--root", default=None,
        help=argparse.SUPPRESS)
    return parser.parse_args(argv)


def default_dict_path():
    """Path of the dictionary shipped next to this script."""
    return Path(__file__).resolve().parent / "metrics-zstd.dict"


def run_check(root):
    """Generate the default dictionary and compare it to the shipped file."""
    lines = generate(
        root, [PLACEHOLDER_ONION], [DEFAULT_PORT],
        include_signing=True, include_hs=True)
    text = validate(root, lines)
    path = default_dict_path()
    if not path.is_file():
        die("missing %s; regenerate with -o %s" % (path, path))
    on_disk = path.read_text(encoding="utf-8")
    if on_disk != text:
        diff = "".join(difflib.unified_diff(
            on_disk.splitlines(True), text.splitlines(True),
            fromfile=str(path.name), tofile="generated", n=2))
        sys.stderr.write(diff[:8000])
        die("%s is stale; regenerate it with this script" % path.name)
    n_help = sum(1 for line in lines if line.startswith("# HELP "))
    sys.stderr.write(
        "metrics-zstd-dict: %d metrics, %d lines, matches sources\n" % (
            n_help, len(lines)))


def main(argv):
    """Entry point. Returns a process status code."""
    try:
        args = parse_args(argv)
        root = Path(args.root) if args.root else repo_root()
        if args.check:
            run_check(root)
            return 0
        onions = [PLACEHOLDER_ONION]
        if args.onion:
            onions = [normalize_onion(item) for item in args.onion]
        ports = [DEFAULT_PORT]
        if args.port:
            ports = []
            for port in args.port:
                if port < 0 or port > 65535:
                    die("port %s is outside 0..65535" % port)
                ports.append(port)
        if args.no_hs and args.onion:
            die("--onion has no effect with --no-hs")
        lines = generate(
            root, onions, ports,
            include_signing=not args.no_signing_cert,
            include_hs=not args.no_hs)
        # Still reject a generator that drifts from the formatter, even when
        # the caller asked for a subset of families.
        assert_sed_compatible(lines)
        text = render(lines)
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
        else:
            try:
                sys.stdout.write(text)
            except BrokenPipeError:
                try:
                    sys.stdout.close()
                except OSError:
                    pass
                return 0
        return 0
    except CheckFailure as exc:
        sys.stderr.write("metrics-zstd-dict: %s\n" % exc)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
