#!/usr/bin/env python3

# owinec - Open Windows Event Collector
# Simple Object Access Protocol (SOAP) implementation
# Lorenz Stechauner, 2020

from __future__ import annotations
from typing import List
import xml.etree.ElementTree as ET
import re
import uuid

namespace = {
    's': 'http://www.w3.org/2003/05/soap-envelope',
    'a': 'http://schemas.xmlsoap.org/ws/2004/08/addressing',
    'n': 'http://schemas.xmlsoap.org/ws/2004/09/enumeration',
    'w': 'http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd',
    'p': 'http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd',
    'b': 'http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd',
    'e': 'http://schemas.xmlsoap.org/ws/2004/08/eventing'
}

namespace_ = {
    'xmlns:s': 'http://www.w3.org/2003/05/soap-envelope',
    'xmlns:a': 'http://schemas.xmlsoap.org/ws/2004/08/addressing',
    'xmlns:n': 'http://schemas.xmlsoap.org/ws/2004/09/enumeration',
    'xmlns:w': 'http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd',
    'xmlns:p': 'http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd',
    'xmlns:b': 'http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd',
    'xmlns:e': 'http://schemas.xmlsoap.org/ws/2004/08/eventing'
}


ACTION_ENUMERATE = 'http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate'
ACTION_ENUMERATE_RESPONSE = 'http://schemas.xmlsoap.org/ws/2004/09/enumeration/EnumerateResponse'
ACTION_SUBSCRIBE = 'http://schemas.xmlsoap.org/ws/2004/08/eventing/Subscribe'

RESOURCE_URI_SUBSCRIPTION = 'http://schemas.microsoft.com/wbem/wsman/1/SubscriptionManager/Subscription'
RESOURCE_URI_EVENT_LOG = 'http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog'

ADDRESS_ANONYMOUS = 'http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous'

PATTERN_TIME = re.compile(r'PT(\d+\.\d+)([S])')


def _get_time(time_str: str) -> float:
    match = PATTERN_TIME.fullmatch(time_str)
    if not match:
        raise AssertionError()
    val = float(match.group(1))
    if match.group(2) == 'S':
        val *= 1
    return val


class Action:
    def __init__(self, identifier: str):
        self.id = identifier

    def __repr__(self) -> str:
        return self.id

    def __str__(self) -> str:
        for name, value in globals().items():
            if name.startswith('ACTION_') and value == self.id:
                return name[7:]
        raise NameError('Invalid action identifier')


class ResourceURI:
    def __init__(self, identifier: str):
        self.id = identifier

    def __repr__(self) -> str:
        return self.id

    def __str__(self) -> str:
        for name, value in globals().items():
            if name.startswith('RESOURCE_URI_') and value == self.id:
                return name[13:]
        raise NameError('Invalid resource uri identifier')


class Envelope:
    def __init__(self, resource_uri: str, action: str, operation_id: str, message_id: str = None):
        self.resource_uri = ResourceURI(resource_uri) if resource_uri else None
        self.action = Action(action) if action else None
        self.operation_id = operation_id
        self.id = message_id or uuid.uuid4()

    @staticmethod
    def load(tree: ET.ElementTree) -> Envelope:
        envelope = tree.getroot()
        resource_uri = envelope.find('s:Header/w:ResourceURI', namespace)
        action = envelope.find('s:Header/a:Action', namespace)
        message_id = envelope.find('s:Header/a:MessageID', namespace)
        operation_id = envelope.find('s:Header/p:OperationID', namespace)
        envelope = Envelope(
            resource_uri.text.strip() if resource_uri != None else None,
            action.text.strip() if action != None else None,
            operation_id.text.strip() if operation_id != None else None,
            message_id.text.strip() if message_id != None else None
        )

        return envelope

    def xml(self) -> ET.Element:
        pass

    def dump(self) -> str:
        return ET.tostring(self.xml)

    def __repr__(self) -> str:
        return f'<Envelope {{{repr(self.action)} {repr(self.resource_uri)}}}>'

    def __str__(self) -> str:
        return f'<Envelope {{{str(self.action)} {str(self.resource_uri)}}}>'


class EnumerateSubscript(Envelope):
    def __init__(self, operation_id: str):
        super().__init__(RESOURCE_URI_SUBSCRIPTION, ACTION_ENUMERATE, operation_id)

    @staticmethod
    def load(tree: ET.ElementTree) -> Envelope:
        pass

    def xml(self) -> ET.Element:
        pass


class EnumerateResponseEnvelope(Envelope):
    pass


class HeartbeatEnvelope(Envelope):
    pass


class AckEnvelope(Envelope):
    pass


if __name__ == '__main__':
    env = Envelope.load(ET.parse('raw/01-client.raw.xml'))
    print(env)
