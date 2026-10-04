# LINQ functions reference

One line per Devo LINQ operation (function), distilled from the "How does it work in LINQ?"
sections of the Devo operations reference. Search-window (UI) instructions are omitted.

**How to use this file**

- Grep for the function name followed by `(`, e.g. `grep -n 'ispublic(' linq-functions.md`,
  or grep a keyword such as `geo`, `regex`, `json`, `hash`.
- Line format: `name(args)` [aliases / operator forms] → return type — what it does.
- Several `name(...)` forms on one line are alternative signatures of the same function.
- **(agg)** = aggregation function: only valid in `select` after a `group` clause,
  e.g. `group every 5m by srcIp every 5m select count() as n`.
- **(filter)** = returns boolean; use it in `where` to filter or in `select ... as` to create a column.
  Everything else is used as `select fn(...) as newField`.
- Argument type names: `string`, `integer`, `float`, `boolean`, `timestamp`, `duration`, `ip` (IPv4),
  `ip6`, `net4`, `net6`, `mac`, `regexp` (built with `re("...")`), `template` (built with
  `template("...")`), `json`, `jq`, `array`, `set`, `map`, `tuple`, `boxar(int1)` (byte array),
  `dc` (HyperLogLog++ sketch), `geocoord`, `packet`. `[opt]` marks an optional argument.
- "(check page)" = the source page is ambiguous or looks wrong; verify before relying on it.
  Source pages live in `operations/<name>.md` of the docs repo.

## Contents

- [Most useful for security investigations](#most-useful-for-security-investigations)
- [Things that do not exist (use these instead)](#things-that-do-not-exist-use-these-instead)
- Full catalogue:
  [Aggregation](#aggregation-operations) ·
  [Calculation](#calculation-group) ·
  [Codification](#codification-group) ·
  [Conversion](#conversion-group) ·
  [Detection](#detection-group) ·
  [Extraction](#extraction-group) ·
  [Geolocation](#geolocation-group) ·
  [JSON](#json-group) ·
  [Lookup](#lookup-operations) ·
  [Packet](#packet-group) ·
  [Time](#time-group) ·
  [Web connection](#web-connection-group)

---

## Most useful for security investigations

**String matching / regex**

- `has(field, "a", "b"...)` / `field -> "a"` — case-sensitive contains any: `where has(cmdline, "mimikatz")`
- `weakhas(field, "x")` — case-insensitive contains: `where weakhas(userAgent, "curl")`
- `toktains(field, "tok" [, left_ext, right_ext])` — token (delimiter-bounded) match: `where toktains(uri, "admin")`
- `weaktoktains(field, "tok" ...)` — case-insensitive token match: `where weaktoktains(headers, "language")`
- `matches(field, re("..."))` / `field ~ re("...")` — regex match (filter): `where cmdline ~ re("-enc(odedcommand)? ")`
- `peek(field, re("...") [, group])` — first regex match / capture group as string: `select peek(machine, '[0-9a-f]{8}') as id` (pattern given as a quoted string on the page)
- `startswith(s, "p")` / `endswith(s, "x")` — prefix/suffix test: `where endswith(domain, ".ru")`
- `eqic(a, b)` — case-insensitive equality: `where eqic(user, "administrator")`
- `` `in`(v, set_or_net) `` / `v <- x` — membership in string/set/array/map/net: `where srcIp <- 10.0.0.0/8`
- `subs(s, re("..."), template("\\1"))` / `subsall(...)` — regex replace first/all
- `replace(s, "a", "b")` / `replaceall(s, "a", "b")` — literal replace first/all
- `shannonentropy(s)` → float — entropy of a string (DGA / random-name detection)
- `levenshtein(a, b)` → integer — edit distance (typosquat detection); also `damerau`, `osa`, `hamming`

**IP / network**

- `ispublic(ip)` / `isprivate(ip)` — IPv4 public/private test: `where ispublic(srcIp)`
- `ip4("1.2.3.4")` → ip — string/integer to IPv4; `ip6(...)` → ip6
- `net4("10.0.0.0/8")` → net4 — CIDR literal; test membership with `ip <- net4(...)`
- `peek(ip, net_array)` — first matching prefix from an array of net4/net6
- `countrycode(ip)` → string — ISO-3166-1 alpha-2 country of an IP (GeoIP2)
- `asn(ip)` → integer / `asorg(ip)` → string — autonomous system number / owner
- `isp(ip)`, `org(ip)`, `city(ip)`, `connectiontype(ip)` → string — GeoIP enrichment
- `reputation(ip)` → string tags / `reputationscore(ip)` → integer — IP reputation lists
- `purpose(ip)` → string — legal use / purpose of an IPv4 address

**Hostname / URL / user agent**

- `rootdomain(host)`, `subdomain(host)`, `topleveldomain(host)`, `publicsuffix(host)` → string
- `urihost(uri)`, `uripath(uri)`, `uriquery(uri)`, `uriport(uri)` → URL parts
- `urldecode(s)` → string — decode `%xx` escapes
- `sbl(domain)` → string — Squid blacklist category of a domain
- `uaisrobot(ua)` → boolean; `uaname(ua)`, `uaosname(ua)`, `uadevicetype(ua)` → string

**Hashing / encoding**

- `md5(s)`, `sha1(s)`, `sha256(s)`, `sha512(s)` → boxar(int1) — wrap in `to16(...)` for a hex string
- `from64(s)` → byte array; `fromutf8(from64(s))` → decoded base64 text

**Time**

- `formatdate(ts, "YYYY-MM-DD HH:mm:ss" [, tz, locale])` → string
- `parsedate(s, "DD/MM/YYYY HH:mm:ss" [, tz, locale])` → timestamp
- `timestamp(epoch_ms_or_string)` → timestamp; `epoch(ts)` → integer ms
- `period(ts, 1h)` → timestamp — bucket timestamps; `hour(ts [, tz])`, `dayofweek(ts [, tz])` → integer
- `now()` is not a documented function; use `today()`, `yesterday()`, `midnight()` (all → timestamp)
- **Time arithmetic:** `a - b` on two timestamps gives a duration, which `avg()`, `round()` and
  most arithmetic don't accept. Use `epoch(a) - epoch(b)` (integer milliseconds), then
  `/ 1000`, `round(...)`, `avg(...)`: `select (epoch(eventdate) - epoch(timestamp(CreationTime))) / 60000 as lag_min`.

**JSON / parsing / splitting**

- `jsonparse(s)["key"]` → json — parse JSON and pick a key; wrap with `str(...)` for a string
- **jq subset:** `jqcompile` supports paths (`.a.b`, `.[0]`, `.[]`) but not filters such as `select(...)` or `[]?`:
  pull the JSON with `stringify(field)` and filter client-side.
- `jqeval(jqcompile(".a.b"), jsonparse(s))` → json — jq path extraction
- `split(s, "sep", n)` → string (n-th piece, 0-based) / `split(s, "sep")` → array
- `splitre(s, re("..."), n)` → string; `substring(s, start [, len])` → string
- `lower(s)`, `upper(s)`, `trim(s)`, `length(s)` — normalise strings

**Null handling / conditionals / casting**

- `nvl(x, default)` / `x ?: default` — coalesce null
- `isnull(x)` / `isnotnull(x)` / `isempty(s)` — filters
- `ifthenelse(cond, a, b)` — if/else: `ifthenelse(dstPort = 3389, "RDP", "other")`
- `decode(f, v1, r1, v2, r2 ..., otherwise)` — switch/case
- `int(x)`, `float(x)`, `str(x)` — type casts

**Aggregation (after `group`)**

- `count()` / `count(field)` → integer — events / non-null values
- `sizedistinct(field)` → integer — exact distinct count; `hllppcount(field)` → float — approximate distinct count
- `sum`, `avg`, `min`, `max`, `median`, `percentile(field, 95)`, `stddev` — numeric stats
- `first(f)` / `last(f)` (and `nnfirst` / `nnlast` for non-null) — earliest/latest value by eventdate
- `collectdistinct(f)` → set; `collect(f)` → array; `collectcompact(f)` → map value→count

## Things that do not exist (use these instead)

- No `countdistinct` / `dcount` page: use `sizedistinct(f)` (exact) or `hllppcount(f)` (approximate).
- No `coalesce`: use `nvl(a, b)` or `a ?: b`.
- No `toint` / `tointeger`: the integer cast is `int(x)` (`bigint(x)` for large values).
- IP literals in sets are typed: `{1.2.3.4, 5.6.7.8}` is a `set(ip4)`, so `f in {1.2.3.4}` on a
  **string** field fails with ``No function named `in` … str, set(ip4)``. Quote them
  (`f in {"1.2.3.4", "5.6.7.8"}`) for string fields; unquoted is right for `ip4` fields.
- `hllppcount(f)` is an approximate distinct count (a float; round it for display). Use
  `sizedistinct(f)` when the exact number matters and the group is small enough. Summed or
  merged across time chunks it is not additive: the largest per-window value is only a lower bound.
- No `contains`/`like`: use `has`, `weakhas`, `toktains`, `matches`.
- MaxMind-specific GeoIP functions (`mm2country`, `mm2asn`, `mm2asorg`, `mm2city`, `mm2con`,
  `mm2coordinates`, `mm2isp`, `mm2latitude`, `mm2longitude`, `mm2org`, `mm2postalcode`,
  `mm2subdivision1`, `mm2subdivision2`, `mm2accuracyradius`, and legacy `mmcountry`, `mmasn`,
  `mmasowner`, `mmcity`, `mmisp`, `mmorg`, `mmregion`, `mmregionname`, `mmspeed`, …) are
  **deprecated**; use the agnostic versions (`countrycode`, `asn`, `asorg`, `city`, …).

---

## Aggregation operations

All are **(agg)**: use in `select` after `group every <period> [by f1, f2...]`.

- `avg(numeric)` → integer/float — average (nulls count as values; see nnavg).
- `collect(field)` → array — collects values in event order.
- `collectcompact(field)` → map — map of value → repetitions, in event order.
- `collectdistinct(field)` → set — set of distinct values.
- `collectsorted(field)` → array — floats collected into a sorted array.
- `count()` / `count(field)` → integer — number of events / non-null values of field.
- `first(field)` → same as arg — first value per group (by eventdate).
- `nnfirst(field)` → same as arg — first non-null value per group.
- `hllpp(field)` → dc — HyperLogLog++ sketch of distinct values (feed to `estimation`).
- `hllppcount(field)` → float — HyperLogLog++ estimated distinct count.
- `last(field)` → same as arg — last value per group (by eventdate).
- `nnlast(field)` → same as arg — last non-null value per group.
- `max(field)` / `max(f1, f2, ...)` → integer/float/string/timestamp — highest value (strings: last alphabetically).
- `median(integer)` → integer — median (percentile 50, 2nd quartile).
- `min(field)` / `min(f1, f2, ...)` → integer/float/string/timestamp — lowest value (strings: first alphabetically).
- `nnavg(numeric)` → integer/float — average excluding nulls.
- `nnstddev(numeric)` → integer/float — biased standard deviation excluding nulls.
- `nnustddev(numeric)` → integer/float — unbiased standard deviation excluding nulls.
- `nnvar(numeric)` → float — biased variance excluding nulls.
- `nnuvar(numeric)` → float — unbiased variance excluding nulls (page text says "biased"; check page).
- `percentile(field, n)` → integer — value at percentile n (linear interpolation), e.g. `percentile(timeTaken, 80)`.
- `percentile5(integer)` → integer — 5th percentile.
- `percentile10(integer)` → integer — 10th percentile.
- `percentile25(integer)` → integer — 25th percentile / 1st quartile.
- `percentile75(integer)` → integer — 75th percentile / 3rd quartile.
- `percentile90(integer)` → integer — 90th percentile.
- `percentile95(integer)` → integer — 95th percentile.
- `sizedistinct(field)` → integer — number of distinct values in the group.
- `stddev(numeric)` → integer/float — biased standard deviation.
- `ustddev(numeric)` → integer/float — unbiased standard deviation.
- `sum(numeric)` → integer/float — total.
- `sum2(numeric)` → integer/float — sum of squares.
- `var(numeric)` → float — biased variance.
- `uvar(numeric)` → float — unbiased variance.

## Calculation group

- `abs(number)` → integer/float — absolute value.
- `add(a, b, ...)` [`a + b`] → float/integer/duration/timestamp/string — add numbers or durations, timestamp + duration, or concatenate strings/tuples.
- `acos(number)` → float — arc cosine.
- `asin(number)` → float — arc sine.
- `atan(number)` / `atan(y, x)` → float — arc tangent (two-arg form uses coordinates).
- `band(a, b)` [`a & b`] → integer / set / map — bitwise AND of integers; intersection of two sets or maps.
- `bnot(integer)` [`~(integer)`] → integer — bitwise NOT.
- `bor(int1, int2)` [`int1 | int2`] → integer — bitwise OR.
- `bxor(int1, int2)` [`int1 ^ int2`] → integer — bitwise XOR.
- `lshift(int, n)` [`int << n`] → integer — shift bits left n places.
- `rshift(int, n)` [`int >> n`] → integer — shift bits right n places.
- `urshift(int, n)` [`int >>> n`] → integer — unsigned right shift.
- `cbrt(number)` → integer/float — cube root.
- `ceil(number)` → integer/float — round up.
- `cos(number)` → float — cosine.
- `cosh(number)` → integer (per page) — hyperbolic cosine.
- `div(a, b)` [`a / b`] → integer / duration — division (integer quotient when both are integers); `duration / integer`.
- `rdiv(a, b)` [`a \ b`] → float — real (floating-point) division.
- `rem(int1, int2)` [`int1 % int2`] → integer — division remainder.
- `mod(int1, int2)` [`int1 %% int2`] → integer — modulo.
- `e()` → float — Euler's number.
- `exp(number)` → float — e raised to number.
- `filter(array_or_set, 'bool_expr_with_ _')` → same as first arg — keep elements for which the expression (with `_` as the element) is true, e.g. `filter(collectdistinct(cmd), 'has(_,"rm -rf")')`.
- `floor(number)` → integer/float — round down.
- `log(number)` / `log(base, number)` → float — natural or arbitrary-base logarithm.
- `log2(number)` → float — base-2 logarithm.
- `log10(number)` → float — base-10 logarithm.
- `map(array_or_set, 'expr_with_ _')` → array/set — apply an expression to every element, e.g. `map(arr, 'ge(_,300)')`.
- `mul(a, b, ...)` [`a * b`] → integer/float/duration — multiply numbers, or integer × duration.
- `pi()` → float — Pi.
- `pow(base, exponent)` → integer/float — power.
- `round(number [, decimals])` → integer/float — round to nearest / to n decimals.
- `signum(number)` → integer — sign: 1, -1 or 0.
- `sin(number)` → float (page says integer) — sine.
- `sinh(number)` → integer (per page) — hyperbolic sine.
- `sqrt(number)` → float — square root.
- `sub(a, b)` / `sub(a)` [`a - b`, `- a`] → float/integer/duration/timestamp — subtraction (numbers, durations, timestamp − timestamp, timestamp − duration) or negation.
- `tan(number)` → float (page says integer) — tangent.
- `tanh(number)` → integer (per page) — hyperbolic tangent.

## Codification group

- `md5(string)` → boxar(int1) — MD5 hash as byte array (use `to16()` for hex).
- `sha1(string)` → boxar(int1) — SHA1 hash as byte array.
- `sha256(string)` → boxar(int1) — SHA256 hash as byte array.
- `sha512(string)` → boxar(int1) — SHA512 hash as byte array.

## Conversion group

- `estimation(dc)` → float — approximate count from a HyperLogLog++ `dc` value.
- `bag(array)` → map — map of each element → count, e.g. `bag([0,1,1]) === {0:1, 1:2}`.
- `duration(string_or_int)` → duration — convert e.g. `"1d"`, `"5m"` strings or integers to duration.
- `formatdate(ts, format [, tz [, locale]])` → string — format timestamp, e.g. `formatdate(eventdate, "YYYY-MM-DD HH:mm")`; literals in `[ ]`.
- `formatnumber(number, format [, locale])` → string — e.g. `formatnumber(bytes, "#,###", "es_ES")`.
- `hex8(string)` → integer — integer from a hexadecimal string.
- `from16(hex_string)` → boxar(int1) — byte array from hex string (inverse of to16).
- `from64(base64_string)` → boxar(int1) — byte array from base64 (inverse of to64).
- `fromutf8(boxar)` → string — decode byte array as UTF-8, e.g. `fromutf8(from64(s))`.
- `fromz85(z85_string)` → boxar(int1) — byte array from Z85/base85.
- `humanSize(integer [, boolean])` → string — human-readable size (binary KiB by default; `false` = decimal KB).
- `pack(dc)` → boxar(int1) — HyperLogLog++ `dc` to byte array.
- `unpackhllpp(boxar)` → dc — byte array back to HyperLogLog++ `dc`.
- `join(array [, separator])` → string — join string array, e.g. `join(["a","b"], "#")` → `a#b`; null separator = no separator.
- `lower(string)` → string — lowercase.
- `mkarray(v1, v2, ...)` [`[v1, v2]`] → array — build an array.
- `mkboxar(int1, int2, ...)` → boxar(int1) — byte array from integers.
- `mkmap(k1, v1, k2, v2, ...)` [`{k:v}`] → map — build a map.
- `mkset(v1, v2, ...)` [`{v1, v2}`] → set — build a set.
- `mktuple(v1, v2, ...)` [`(v1, v2)`] → tuple — build a tuple.
- `parsedate(string, format [, tz [, locale]])` → timestamp — parse a date string, e.g. `parsedate(s, "YYYY-MM-DD[T]HH:mm:ss.SSS", "UTC")`; returns null if the format does not match.
- `re(string)` → regexp — build a regular expression for matches/subs/splitre/peek.
- `replaceall(string, search, replacement)` → string — replace every literal occurrence (case sensitive).
- `replace(string, search, replacement)` → string — replace the first literal occurrence (case sensitive).
- `reverse(string_or_boxar)` → string — reverse contents.
- `shannonentropy(string)` → float — Shannon entropy of a string.
- `split(string, sep)` → array / `split(string, sep, n)` [`split(s, sep)[n]`] → string — split; n counts from 0.
- `splitre(string, re("..."), n)` → string — split by regex and return piece n (from 0).
- `startswith(string, prefix)` → boolean **(filter)** — prefix test.
- `subs(string, re("..."), template("...") [, fail_value])` → string — replace first regex match; template supports `\\1` groups.
- `subsall(string, re("..."), template("..."))` → string — replace all regex matches.
- `substring(string, start [, length])` → string — substring from 0-based start.
- `template(string)` → template — replacement template for subs/subsall (supports capture groups).
- `timestamp(integer_or_string)` → timestamp — epoch milliseconds or formatted date string to timestamp.
- `array(set)` → array — convert a set to an array.
- `hex(integer)` → string — integer to hexadecimal string.
- `to16(boxar)` → string — byte array to hex string (use with md5/sha*).
- `to64(boxar)` → string — byte array to base64 string.
- `bigint(x)` → integer — big integer from number string, float (truncated), mac or json number.
- `bool(json_boolean)` → boolean — JSON boolean value to boolean.
- `float(x)` → float — from number string, integer or json number.
- `image(base64_string)` → image — base64 string (e.g. `"png;base64;..."`) to image.
- `int(x)` → integer — from number string, float (truncated), mac or json number.
- `ip4(string_or_int)` → ip — to IPv4 address.
- `net4(string_or_int)` → net4 — to IPv4 network, e.g. `net4("192.0.2.0/24")`.
- `ip6(string_or_ip)` → ip6 — to IPv6 address.
- `compatible(ip)` → ip6 — IPv4-compatible IPv6 address.
- `mapped(ip)` → ip6 — IPv4-mapped IPv6 address.
- `net6(string)` → net6 — to IPv6 network, e.g. `net6("2001:db8::/64")`.
- `translated(ip)` → ip6 — IPv4-translated IPv6 address.
- `mac(string_or_int)` → mac — to MAC address.
- `set(array)` → set — convert an array to a set.
- `str(x)` → string — integer/float/timestamp/ip/geocoord/mac/json string to string.
- `stringify(json)` → string — serialise any JSON value to string.
- `toutf8(string)` → boxar(int1) — encode UTF-8 string as bytes.
- `toz85(boxar)` → string — byte array to Z85 string.
- `trim(string)` → string — strip leading and trailing whitespace.
- `ltrim(string)` → string — strip leading whitespace.
- `rtrim(string)` → string — strip trailing whitespace.
- `upper(string)` → string — uppercase.

## Detection group

- `a and b and ...` → boolean **(filter)** — logical AND (operator form).
- `at(x, n)` [`x[n]`] → element type — element n of tuple/array/map; `at(json, "key")` for JSON; optional 3rd arg `final` for array slices.
- `at0(tuple)` → element — first element of a tuple.
- `at1(tuple)` → element — second element of a tuple.
- `atend(tuple)` → element — last element of a tuple.
- `ifthenelse(boolean, then, else)` → type of then/else — conditional value.
- `has(value, s1, s2, ...)` [`value -> s`] → boolean **(filter)** — case-sensitive contains any of the strings; value may be string, array, set or map.
- `weakhas(string, s)` → boolean **(filter)** — case-insensitive contains.
- `toktains(string, token [, left_ext [, right_ext]])` → boolean **(filter)** — contains token (delimited by ASCII symbols); booleans allow alphanumerics on left/right.
- `weaktoktains(string, token [, left_ext [, right_ext]])` → boolean **(filter)** — case-insensitive toktains.
- `decode(field, v1, r1 [, v2, r2 ...] [, otherwise])` → type of results — switch/case mapping.
- `dropnulls(array)` → array — remove nulls.
- `damerau(s1, s2)` → integer — Damerau edit distance.
- `hamming(s1, s2)` → integer — Hamming distance.
- `levenshtein(s1, s2)` → integer — Levenshtein distance.
- `osa(s1, s2)` → integer — optimal string alignment distance.
- `endswith(string, suffix)` → boolean **(filter)** — suffix test.
- `eq(a, b)` [`a = b`] → boolean **(filter)** — equality (same type).
- `eqic(s1, s2)` → boolean **(filter)** — case-insensitive string equality.
- `ge(a, b)` [`a >= b`] → boolean **(filter)** — greater or equal.
- `gt(a, b)` [`a > b`] → boolean **(filter)** — greater than.
- `indexof(array, value)` → integer (page says Array; check page) — index of first occurrence, -1 if absent.
- `isempty(string)` → boolean **(filter)** — string is empty.
- `` `in`(v1, v2..., container) `` [`v <- container`] → boolean **(filter)** — any value is a member of a string, set, array, map (keys), net4 or net6; e.g. `` where `in`(clientIp, 198.51.100.0/24) ``.
- `weakin(value, string)` → boolean **(filter)** — case-insensitive "value is contained in string".
- `isnotnull(field)` → boolean **(filter)** — not null.
- `isnull(field)` → boolean **(filter)** — is null.
- `keys(map)` → set — the map's keys.
- `length(string)` → integer — string length.
- `le(a, b)` [`a <= b`] → boolean **(filter)** — less or equal.
- `lt(a, b)` [`a < b`] → boolean **(filter)** — less than.
- `locate(string, substring)` → position (page says string; check page) — 0-based position of first occurrence, case sensitive.
- `matches(string, re("..."))` [`string ~ re("...")`] → boolean **(filter)** — regex match.
- `not b` → boolean **(filter)** — logical NOT (operator form), e.g. `where not isempty(city)`.
- `ne(a, b)` [`a /= b`] → boolean **(filter)** — not equal.
- `nvl(field, value_when_null)` [`field ?: value`] → type of args — null coalesce.
- `a or b or ...` → boolean **(filter)** — logical OR (operator form).
- `peek(ip, net_array)` → net4/net6 — first network prefix in the array that contains the address.
- `peek(string, regexp [, group])` → string — first substring matching the regex (or capture group n; 0 = whole match).
- `sort(array [, ascending_bool])` → array — sort ascending; `false` sorts descending.
- `values(map)` → array — the map's values.

## Extraction group

- `anymatches(setname, nameglob("pattern"))` → boolean **(filter)** — any table name in a set matches a glob; only field is `tables` in `all.data` (global search), e.g. `where anymatches(tables, nameglob("siem.**"))`.
- `nameglob(string)` → namepattern — glob pattern (`*` one level, `**` any levels) for use only inside `anymatches`.
- `pragmavalue(language, query, pragma_key)` → string — extract a pragma value (e.g. `tz`) from a query string.
- `tablename(language, query)` → string — extract the table name from a query string, e.g. `tablename("LINQ", "from a.b.c ...")`.

## Geolocation group

GeoIP (MaxMind GeoIP2 data, agnostic names; each accepts `ip` or `ip6`):

- `accuracyradius(ip)` → float — accuracy radius in km (67% confidence) around the location.
- `asorg(ip)` → string — organisation owning the IP's ASN.
- `asn(ip)` → integer — autonomous system number.
- `city(ip)` → string — city name.
- `connectiontype(ip)` → string — Dialup, Cable/DSL, Corporate or Cellular.
- `coordinates(ip)` → geocoord — latitude/longitude.
- `countrycode(ip)` → string — ISO-3166-1 alpha-2 country code.
- `isp(ip)` → string — ISP name.
- `latitude(ip)` → float — approximate latitude.
- `longitude(ip)` → float — approximate longitude.
- `org(ip)` → string — organisation name.
- `postalcode(ip)` → string — nearby postal code.
- `subdivision1code(ip)` → string — level-1 subdivision (region).
- `subdivision2code(ip)` → string — level-2 subdivision.

ISO-3166-1 country/continent codes (input: any country/continent identification string):

- `continentalpha2(string)` → string — continent alpha-2 code.
- `continentname(string)` → string — continent name.
- `countryalpha2(string)` → string — country alpha-2 code.
- `countrycontinent(string)` → string — continent code of a country.
- `countryalpha3(string)` → string — country alpha-3 code.
- `countrylatitude(string)` → float — country latitude.
- `countrylongitude(string)` → float — country longitude.
- `countryname(string)` → string — country name, e.g. from a code.

Geocoord:

- `distance(geocoord1, geocoord2)` → float — distance in metres.
- `geocoord(string)` → geocoord — from a latlon (sexagesimal) or geohash string.
- `coordsystem(geocoord)` → string — `latlon` or `geohash`.
- `geohash(geocoord [, size])` / `geohash(string)` → geocoord — to geohash geocoord.
- `geohashstr(geocoord [, size])` → string (page says geocoord; check page) — geohash as string.
- `latitude(geocoord)` → float — latitude of a geocoord.
- `latlon(lat, lon)` / `latlon(geocoord)` / `latlon(string)` → geocoord — latlon geocoord.
- `longitude(geocoord)` → float — longitude of a geocoord.
- `parsegeo(string)` → geocoord — parse strict `:type:value` format (from reprgeo).
- `reprgeo(geocoord)` → string (page says geocoord; check page) — represent as `:type:value`.
- `gridlatlon(geocoord, lat_prec, lon_prec)` / `gridlatlon(geocoord, grid_size)` → geocoord — round to a grid.

## JSON group

- `jqeval(jq, json)` → json — evaluate a jq filter, e.g. `jqeval(jqcompile(".a.b"), jsonparse(s))`; wrap in `str()`/`int()` to convert.
- `jqcompile(".path")` → jq — compile a jq filter string.
- `label(json_value)` → string — JSON type of a value (use after jqeval).
- `jsonparse(string)` / `jsonparse(string)["key"]` → json — parse a JSON string; null if invalid JSON or key missing.

## Lookup operations

- `lu("Lookup_name", "Lookup_field", key_field)` → type of lookup field — value from a lookup on key match.
- `hlut("Lookup_name", "Lookup_field", key_field [, timestamp_field])` → type of lookup field — history lookup, optionally time-correlated.
- `hlurjson("Lookup_name", key_field, timestamp_field)` → json — whole row of a time-range lookup as JSON.

## Packet group

All take a `packet` field.

- `etherdst(packet)` → mac — Ethernet destination MAC.
- `etherpayload(packet)` → boxar(int1) — Ethernet payload.
- `ethersrc(packet)` → mac — Ethernet source MAC.
- `etherstatus(packet)` → string — Ethernet status.
- `ethertag(packet)` → string — Ethernet tag.
- `ethertype(packet)` → integer — EtherType.
- `hasether(packet)` → boolean — has an Ethernet frame.
- `hasip4(packet)` → boolean — has an IPv4 datagram.
- `hastcp(packet)` → boolean — has a TCP segment.
- `hasudp(packet)` → boolean — has a UDP datagram.
- `ip4dst(packet)` → ip — IPv4 destination address.
- `ip4ds(packet)` → integer — DSCP.
- `ip4ecn(packet)` → integer — ECN.
- `ip4flags(packet)` → integer — IPv4 flags.
- `ip4fragment(packet)` → integer — fragment offset.
- `ip4cs(packet)` → integer — header checksum.
- `ip4hl(packet)` → integer — header length (IHL).
- `ip4ident(packet)` → integer — identification field.
- `ip4payload(packet)` → boxar(int1) — IPv4 payload.
- `ip4proto(packet)` → integer — protocol field.
- `ip4src(packet)` → ip — IPv4 source address.
- `ip4status(packet)` → string — IPv4 status.
- `ip4ttl(packet)` → integer — TTL.
- `ip4len(packet)` → integer — total length.
- `ip4tos(packet)` → integer — type of service.
- `tcpack(packet)` → integer — TCP acknowledgment number.
- `tcpcs(packet)` → integer — TCP checksum.
- `tcpdst(packet)` → integer — TCP destination port.
- `tcpflags(packet)` → integer — TCP flag bits (NS CWR ECE URG ACK PSH RST SYN FIN).
- `tcphl(packet)` → integer — TCP header length.
- `tcppayload(packet)` → boxar(int1) — TCP payload.
- `tcpseq(packet)` → integer — TCP sequence number.
- `tcpsrc(packet)` → integer — TCP source port.
- `tcpstatus(packet)` → string — TCP status.
- `tcpurg(packet)` → integer — TCP urgent pointer.
- `tcpwin(packet)` → integer — TCP window size.
- `udpcs(packet)` → integer — UDP checksum.
- `udpdst(packet)` → integer — UDP destination port.
- `udplen(packet)` → integer — UDP length.
- `udppayload(packet)` → boxar(int1) — UDP payload.
- `udpsrc(packet)` → integer — UDP source port.
- `udpstatus(packet)` → string — UDP status.

## Time group

`tz` = optional time zone string (e.g. `"UTC"`, `"CET"`, `"Europe/Madrid"`); default is the user's time zone.

- `day()` → duration (1d) / `day(ts [, tz])` → integer — day of month, 0-30 (0 = first day).
- `dayname(ts [, locale [, tz]])` → string — name of the day.
- `daynumber(ts [, tz])` → integer — day of month, 1-31.
- `dayofweek(ts [, tz])` → integer — 0-6, 0 = Sunday.
- `dayofyear(ts [, tz])` → integer — 0-364/365.
- `epoch(ts)` → integer — milliseconds since 1970-01-01.
- `hour()` → duration (1h) / `hour(ts [, tz])` → integer — hour 0-23.
- `isleapyear(ts [, tz])` → boolean — leap year test.
- `midnight()` / `midnight(ts [, tz])` → timestamp — start of the day.
- `millisecond()` → duration / `millisecond(ts [, tz])` → integer — 0-999.
- `minute()` → duration (1m) / `minute(ts [, tz])` → integer — 0-59.
- `minuteofday(ts [, tz])` → integer — minutes since midnight.
- `month(ts [, tz])` → integer — 0-11, 0 = January.
- `monthname(ts [, locale [, tz]])` → string — name of the month.
- `monthnumber(ts [, tz])` → integer — 1-12.
- `period(ts, duration_or_int)` → timestamp — align timestamps to the start of a period (UTC based), e.g. `period(eventdate, 15m)`.
- `second()` → duration (1s) / `second(ts [, tz])` → integer — 0-59.
- `secondofday(ts [, tz])` → integer — seconds since midnight.
- `today([tz])` → timestamp — start of the current day.
- `tomorrow([tz])` → timestamp — start of the following day.
- `weekofmonth(ts [, tz])` → integer — 1-5.
- `weekofyear(ts [, tz])` → integer — 1-52.
- `year(ts [, tz])` → integer — year.
- `yesterday([tz])` → timestamp — start of the previous day.

## Web connection group

- `absoluteuri(string)` → boolean **(filter)** — URI is absolute.
- `opaqueuri(string)` → boolean **(filter)** — URI is opaque.
- `publicsuffix(host)` → string — public suffix (e.g. `co.uk`).
- `rootdomain(host)` → string — root domain.
- `rootprefix(host)` → string — everything before and including the root domain (e.g. `www.my.example`).
- `rootsuffix(host)` → string — root domain plus suffix (e.g. `example.co.uk`).
- `subdomain(host)` → string — subdomain part (e.g. `www`).
- `topleveldomain(host)` → string — TLD.
- `httpstatusdescription(integer)` → string — description of an HTTP status code.
- `httpstatustype(integer)` → string — class: Informational, Successful, Redirection, Client Error, Server Error.
- `ipprotocol(integer_or_string)` → string/integer — IP protocol number ↔ name.
- `reputationscore(ip)` → integer — averaged score from public IP reputation sources.
- `reputation(ip)` → string — IPv4 reputation-list tags.
- `purpose(ip)` → string — purpose / legal use of an IPv4 address.
- `host(ip6)` → integer — IPv6 host number.
- `routing(ip6)` → integer — IPv6 routing part.
- `isprivate(ip)` → boolean **(filter)** — IPv4 is private.
- `ispublic(ip)` → boolean **(filter)** — IPv4 is public.
- `sbl(domain)` → string — Squid Black List category (empty if not listed).
- `isip4(ip6)` → boolean — IPv6 carries an IPv4 address.
- `uriauthority(uri)` → string — authority part.
- `urifragment(uri)` → string — fragment (null if none).
- `urihost(uri)` → string — host.
- `uripath(uri)` → string — path.
- `uriport(uri)` → integer — port.
- `uriquery(uri)` → string — query string.
- `urischeme(uri)` → string — scheme.
- `urissp(uri)` → string — scheme-specific part.
- `uriuser(uri)` → string — user info.
- `urldecode(url)` → string — decode `%xx` escape sequences.

User agent (all take a user-agent string):

- `uacompany(ua)` → string — creator company.
- `uacompanyurl(ua)` → string — creator company URL.
- `uadeviceicon(ua)` → string — device type icon.
- `uadeviceinfourl(ua)` → string — device information URL.
- `uadevicetype(ua)` → string — device type.
- `uafamily(ua)` → string — UA family.
- `uaicon(ua)` → string — UA icon.
- `uainfourl(ua)` → string — UA information URL.
- `uaisrobot(ua)` → boolean — UA is a robot/crawler.
- `uaname(ua)` → string — UA name.
- `uaoscompany(ua)` → string — OS creator company.
- `uaoscompanyurl(ua)` → string — OS creator company URL.
- `uaosfamily(ua)` → string — OS family.
- `uaosicon(ua)` → string — OS icon.
- `uaosname(ua)` → string — OS name.
- `uaosurl(ua)` → string — OS URL.
- `uatype(ua)` → string — UA type.
- `uaurl(ua)` → string — UA URL.
- `uaversion(ua)` → string — UA version.
