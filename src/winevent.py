#!/usr/bin/env python3

# Owinec - Open Windows Event Collector
# Windows XML-Format Event Parser
# Copyright (C) 2020, Lorenz Stechauner
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


# https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventrecord?view=dotnet-plat-ext-3.1
# https://docs.microsoft.com/de-at/windows/win32/eventlog/event-identifiers
# https://docs.microsoft.com/de-at/windows/win32/eventlog/event-sources
#
# https://docs.microsoft.com/de-at/windows/win32/wes/windows-event-log
# https://docs.microsoft.com/en-us/windows/win32/eventlog/event-logging
#
# https://github.com/libyal/libevt/blob/master/documentation/Windows%20Event%20Log%20(EVT)%20format.asciidoc

from typing import Dict
import xml.etree.ElementTree as ET


namespace = {'': 'http://schemas.microsoft.com/win/2004/08/events/event'}


def parse(raw: str, keep_rendered_text: bool = False) -> Dict:
    event = {'data': {}}
    tree = ET.fromstring(raw)
    print(tree)

    for data in tree.iterfind('./EventData/Data', namespace):
        key = data.get('Name').strip()
        value = data.text.strip()
        if value.startswith('%%'):
            pass  # TODO
        elif value.isnumeric():
            value = int(value)
        elif value == '-':
            value = None
        event['data'][key] = value

    render_info = tree.find('./RenderingInfo', namespace)
    if keep_rendered_text and render_info is not None:
        event['rendered'] = {
            'locale': render_info.get('Culture').strip(),
            'level': render_info.find('./Level', namespace).text.strip(),
            'task': render_info.find('./Task', namespace).text.strip(),
            'opcode': render_info.find('./Opcode', namespace).text.strip(),
            'channel': render_info.find('./Channel', namespace).text.strip(),
            'provider': render_info.find('./Provider', namespace).text.strip(),
            'keywords': [keyword.text.strip() for keyword in render_info.iterfind('./Keywords/Keyword', namespace)],
            'message': None,
            'comments': [],
            'data': []
        }
        blocks = render_info.find('./Message', namespace).text.strip().split('\n\n')
        event['rendered']['message'] = blocks[0].rstrip('.')
        for block in blocks[1:]:
            if ':\n' in block or ':\t' in block:
                event['rendered']['data'].append(block)
            else:
                event['rendered']['comments'].append(block)

    return event


if __name__ == '__main__':
    with open('raw/event-raw.xml') as f:
        print(parse(f.read(), keep_rendered_text=True))


# https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx

# https://jdhitsolutions.com/blog/powershell/7193/better-event-logs-with-powershell/
#
# I have a very similar function to this. The one thing I’m left wanting is a way to replace all the placeholders with
# their insertion strings. Here’s a summary of the issue that I had written up before.
# >>>>Values like “%%2307” (or with only a single leading “%”) are insertion string placeholders. Messages are formed
# from message text files, which typically are compiled as .DLLs but can also be included in .EXEs (and maybe other)
# resources. The location of these message text files is stored in the registry under subkeys of
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog, that corresponds with the specific logname and source.
# So essentially you have have something like HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\\. Once you
# locate the correct key, the location data is stored in a value named EventMessageFile, which points to the path of the
# .DLL (or other type of file). There can also be a value for CategoryMessageFile, and ParameterMessageFile (these could
# all point to the same file, or different ones). As I understand it, the ParameterMessageFile is where the insertion
# strings are defined for the placeholders which begin with a double percent sign (%%xxxx).
#
# So far I haven’t found any way to parse a message text file for insertion strings which correspond to their numbers.
#
# The only bright side is that the message property of an event has already gone through the process of formatting
# (probably through the use of the FormatMessage function –
# https://docs.microsoft.com/en-us/windows/desktop/api/winbase/nf-winbase-formatmessage), substituting all the
# placeholders with their insertion strings corresponding with the proper language.<<<<<<<
# Care to take up the challenge?
