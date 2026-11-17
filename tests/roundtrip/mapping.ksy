meta:
  id: mapping
doc: "Message type 'mapping'. Written by bitwise-bus. Frames are separated by silences of at least 4000000 ns."
seq:
  - id: sync
    contents: [0x7e]
    doc: "constant"
  - id: id
    type: u1
    doc: "enum"
  - id: count
    type: u2be
    doc: "counter, step 1"
  - id: stamp
    type: u4le
    doc: "timestamp"
  - id: total
    type: u8be
    doc: "length"
  - id: ratio
    type: f4le
    doc: "float"
  - id: wide
    type: f8be
    doc: "float"
  - id: name
    type: str
    size: 4
    encoding: ASCII
    doc: "text"
  - id: stuff
    size: 3
    doc: "payload"
  - id: odd
    size: 3
    doc: "counter, big-endian"
  - id: magic
    contents: [0x34, 0x12]
    doc: "constant"
  - id: tail
    contents: [0xde, 0xad, 0xbe, 0xef]
    doc: "constant"
  - id: checksum
    type: u2be
    doc: "checksum, CRC-16/CCITT-FALSE, over sync to tail (Kaitai does not check it)"
