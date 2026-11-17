# Capture format, version 1

The neutral format every importer produces and every stage reads: a CSV with
one row per *event*.

An event is whatever the capturing tool delivered in one piece with one
timestamp: a single UART byte, a burst of bytes, a whole CAN frame. The format
does not say which, because deciding where frames begin and end is the job of
segmentation, and segmentation needs the events exactly as they were captured.

```csv
# bitwise-capture 1
time_ns,channel,direction,id,data
0,rs485,,,01
1145833,rs485,,,03
2291667,rs485,,,00
```

```csv
# a CAN capture: one event per frame, the identifier in its own column
time_ns,channel,direction,id,data
1500000,can0,rx,0x123,de ad be ef
2500000,can0,rx,0x7e8,03 41 0c 1a f8
```

## Rules

- UTF-8, with LF or CRLF line endings. A byte-order mark at the start is
  skipped.
- Blank lines, and lines whose first non-blank character is `#`, are ignored.
  The first line of a file written by this project is `# bitwise-capture 1`.
- The first remaining line is the header. Column names are case-insensitive and
  may come in any order. Columns this version does not know are ignored, so a
  later version can add some without breaking older readers.
- Every following line has exactly as many fields as the header. Fields are
  separated by commas and trimmed of blanks. **There is no quoting**: a field
  containing `"` is an error, and so is a channel name that would need it.

## Columns

| Column | Required | Meaning |
|---|---|---|
| `data` | yes | The event's bytes: hex digits, two per byte. Bytes may be separated by blanks (`01 03` or `0103`), but not split (`0 1` is an error). Empty means an event with no bytes, such as a break condition. |
| `time_ns` | no | When the event happened, as a signed integer number of **nanoseconds** from an origin the capture chooses. Empty means the tool gave no time. |
| `channel` | no | A label for the wire or interface the event came from (`uart0`, `can1`). Empty is the unnamed channel. |
| `direction` | no | `rx`, `tx`, or empty when unknown. |
| `id` | no | A hexadecimal identifier of at most 8 digits, with or without `0x`: the CAN arbitration ID. Empty means the event has none. |

## Time

- Nanoseconds, as an integer, so that nothing in the file depends on how a
  floating-point number is parsed. Tools that export seconds with a decimal
  fraction are converted by their importer.
- A timestamp is when the event *started*. How long an event lasted is not
  recorded.
- **Time never goes backwards.** Each timed event must be no earlier than the
  most recent timed event before it; equal times are fine. A file that breaks
  this is rejected with the line number rather than silently reordered, because
  the usual cause is a mistake in the export.
- Events without a time may be mixed with timed ones. Whether a stage can work
  from a partly timed capture is for that stage to say.

## Errors

A malformed file is rejected as a whole, and the message names the line:

```
line 7: data: odd number of hex digits in '0a1'
line 9: time goes backwards: 1000 ns after 2000 ns
```

Nothing is guessed and nothing is skipped: a capture that loaded is a capture
that was read in full.

## Writing

The writer always emits the five columns in the order above, bytes as
lowercase pairs separated by a single blank, identifiers as `0x` and lowercase
hex. Reading what was written gives back the same capture, and writing it
again gives back the same bytes.
