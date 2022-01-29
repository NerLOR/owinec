#!/usr/bin/env python3

# owinec - Open Windows Event Collector
# Extract event description from dll
# Lorenz Stechauner, 2020

import pefile


if __name__ == '__main__':
    file = pefile.PE('../test/adtschema.dll')
    strings = list()

    idx = [entry.id for entry in file.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_MESSAGETABLE'])

    directory = file.DIRECTORY_ENTRY_RESOURCE.entries[idx]
    for entry in directory.directory.entries:
        data_rva = entry.directory.entries[0].data.struct.OffsetToData
        size = entry.directory.entries[0].data.struct.Size
        print('Directory entry at RVA', hex(data_rva), 'of size', hex(size))

        data = file.get_memory_mapped_image()[data_rva:data_rva + size]
        offset = 0
        while offset < size:
            ustr_length = file.get_word_from_data(data[offset:offset + 4], 0)
            ustr_flags = file.get_word_from_data(data[offset:offset + 4], 2)
            offset += 4

            if ustr_length == 0:
                continue

            ustr = file.get_string_u_at_rva(data_rva + offset, max_length=ustr_length)
            offset += ustr_length * 2
            print(ustr)


# 0x0D0C
# 0x0DF8
# 0x0EA8
# 0x1024
