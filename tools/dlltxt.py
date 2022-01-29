#!/usr/bin/env python3

# owinec - Open Windows Event Collector
# Extract event description from dll
# Lorenz Stechauner, 2020

import struct


def extract(file_name: str):
    offset = 0x0008
    with open(file_name, 'rb') as dll:
        while True:
            dll.seek(offset, 0)
            signature = dll.read(4)
            if signature != b'EVNT':
                offset += 0x100
            else:
                break
        size, = struct.unpack('<4xI4x', dll.read(12))
        events = []
        for i in range(size):
            evt_id_1, evt_id_2, evt_off, sig = struct.unpack('<H2x12xH2xI8s16x', dll.read(48))
            print(evt_id_1, evt_id_2, evt_off, sig)
            a = dll.tell()
            dll.seek(-evt_off, 1)
            print(dll.read(16))
            dll.seek(a, 0)
            if sig != b'\xcc\xd2\x07\x00\xfc\xd2\x07\x00':
                continue
            events.append({'id': evt_id_2, 'offset': evt_off})
        for event in events:
            print(f'{event["id"]}: {hex(event["offset"])}')
            dll.seek(event['offset'] + 0xd0c, 0)
            print(dll.read(64))


if __name__ == '__main__':
    extract('test/adtschema.dll')

# 0x0D0C
# 0x0DF8
# 0x0EA8
# 0x1024
