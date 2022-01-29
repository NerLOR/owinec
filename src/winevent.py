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

from __future__ import annotations
from typing import Dict
import xml.etree.ElementTree as ET
import datetime

namespace = {'': 'http://schemas.microsoft.com/win/2004/08/events/event'}

KEYWORD_ENUM = {
    # This value indicates that no filtering on keyword is performed when the event is published
    'None':             0x0000_0000_0000_0000,
    # Attached to all response time events
    'ResponseTime':     0x0001_0000_0000_0000,
    # Attached to all Windows Diagnostic Infrastructure (WDI) context events
    'WdiContext':       0x0002_0000_0000_0000,
    # Attached to all Windows Diagnostic Infrastructure (WDI) diagnostic events
    'WdiDiagnostic':    0x0004_0000_0000_0000,
    # Attached to all Service Quality Mechanism (SQM) events
    'Sqm':              0x0008_0000_0000_0000,
    # Attached to all failed security audit events.
    # This keyword should only be used for events in the Security log
    'AuditFailure':     0x0010_0000_0000_0000,
    # Attached to all successful security audit events.
    # This keyword should only be used for events in the Security log
    'AuditSuccess':     0x0020_0000_0000_0000,
    # Attached to transfer events where the related Activity ID (Correlation ID) is a computed value and is not
    # guaranteed to be unique (not a real GUID)
    'CorrelationHint':  0x0010_0000_0000_0000,
    'CorrelationHint2': 0x0040_0000_0000_0000,
    # Attached to events which are raised using the RaiseEvent function
    'EventLogClassic':  0x0080_0000_0000_0000,
}

OPCODE_ENUM = {
    # An event with this opcode is an informational event
    'Info': 0,
    # An event with this opcode is published when an application starts a new transaction or activity. This can be
    # embedded into another transaction or activity when multiple events with the Start opcode follow each other without
    # an event with a Stop opcode
    'Start': 1,
    # An event with this opcode is published when an activity or a transaction in an application ends.
    # The event corresponds to the last unpaired event with a Start opcode.
    'Stop': 2,
    # An event with this opcode is a trace collection start event
    'DataCollectionStart': 3,
    # An event with this opcode is a trace collection stop event
    'DataCollectionStop': 4,
    # An event with this opcode is an extension event
    'Extension': 5,
    # An event with this opcode is published after an activity in an application replies to an event
    'Reply': 6,
    # An event with this opcode is published after an activity in an application resumes from a suspended state.
    # The event should follow an event with the Suspend opcode
    'Resume': 7,
    # An event with this opcode is published when an activity in an application is suspended
    'Susplend': 8,
    # An event with this opcode is published when one activity in an application transfers data or system resources to
    # another activity
    'Send': 9,
    # An event with this opcode is published when one activity in an application receives data
    'Receive': 240
}

LEVEL_ENUM = {
    # This value indicates that not filtering on the level is done during the event publishing
    'LogAlways': 0,
    # This level corresponds to critical errors, which is a serious error that has caused a major failure
    'Critical': 1,
    # This level corresponds to normal errors that signify a problem
    'Error': 2,
    # This level corresponds to warning events. For example, an event that gets published because a disk is nearing
    # full capacity is a warning event
    'Warning': 3,
    # This level corresponds to informational events or messages that are not errors. These events can help trace the
    # progress or state of an application
    'Informational': 4,
    # This level corresponds to lengthy events or messages
    'Verbose': 5
}


class WinEvent:
    def __init__(self, event_id: int, event_data: Dict = None):
        self.provider_name = None
        self.provider_guid = None
        self.source_name = None
        self.id = event_id
        self.version = None
        self.level = None
        self.task = None
        self.opcode = None
        self.keywords = []
        self.timestamp = None
        self.record_id = None
        self.activity_id = None
        self.process_id = None
        self.thread_id = None
        self.channel = None
        self.hostname = None
        self.user_id = None
        self.data = event_data or {}
        self.rendered = {}

    @staticmethod
    def parse(raw: str, keep_rendered_text: bool = False) -> WinEvent:
        tree = ET.fromstring(raw)

        event_id = int(tree.find('./System/EventID', namespace).text.strip())
        event = WinEvent(event_id)
        provider = tree.find('./System/Provider', namespace)
        event.provider_name = provider.get('Name')
        event.provider_guid = provider.get('Guid')
        event.source_name = provider.get('EventSourceName')
        event.version = int(tree.find('./System/Version', namespace).text.strip())
        event.level = int(tree.find('./System/Level', namespace).text.strip())
        event.task = int(tree.find('./System/Task', namespace).text.strip())
        event.opcode = int(tree.find('./System/Opcode', namespace).text.strip())
        keywords = tree.find('./System/Keywords', namespace).text.strip()
        # TODO parse keyword flags (?)
        timestamp = tree.find('./System/TimeCreated', namespace).get('SystemTime')
        timestamp = timestamp[:-7] + '+00:00'
        event.timestamp = datetime.datetime.fromisoformat(timestamp)
        event.record_id = int(tree.find('./System/EventRecordID', namespace).text.strip())
        event.activity_id = tree.find('./System/Correlation', namespace).get('ActivityID')
        execution = tree.find('./System/Execution', namespace)
        event.process_id = int(execution.get('ProcessID'))
        event.thread_id = int(execution.get('ThreadID'))
        event.channel = tree.find('./System/Channel', namespace).text.strip()
        event.hostname = tree.find('./System/Computer', namespace).text.strip()
        security = tree.find('./System/Security', namespace)
        event.user_id = security.get('UserID')

        for data in tree.iterfind('./EventData/Data', namespace):
            key = data.get('Name')
            if type(event.data) != list and (key is None or key == 'param1'):
                event.data = []
            value = data.text.strip()
            if value.startswith('%%'):
                pass  # TODO
            elif value.isnumeric():
                value = int(value)
            elif value == '-':
                value = None
            if type(event.data) == list:
                event.data.append(value)
            else:
                event.data[key] = value

        render_info = tree.find('./RenderingInfo', namespace)
        if keep_rendered_text and render_info is not None:
            event.rendered = {
                'locale': render_info.get('Culture'),
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
            event.rendered['message'] = blocks[0].rstrip('.')
            for block in blocks[1:]:
                if ':\n' in block or ':\t' in block:
                    event.rendered['data'].append(block)
                else:
                    event.rendered['comments'].append(block)

        return event

    def __str__(self) -> str:
        return f'<WinEvent {{{self.hostname}/{self.id} ({self.channel}) #{self.record_id} {self.timestamp}, {self.provider_name}}}>'


if __name__ == '__main__':
    with open('raw/event-raw.xml') as f:
        evt = WinEvent.parse(f.read(), keep_rendered_text=True)
        print(evt)
        print(evt.rendered)


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
