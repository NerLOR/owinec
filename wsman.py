#!/usr/bin/env python3

# owinec - Open Windows Event Collector
# Simple Object Access Protocol (SOAP) implementation
# Lorenz Stechauner, 2020

from __future__ import annotations
from typing import List, Tuple
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
# xmlns:m="http://schemas.microsoft.com/wbem/wsman/1/subscription"

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
ACTION_END = 'http://schemas.microsoft.com/wbem/wsman/1/wsman/End'
ACTION_HEARTBEAT = 'http://schemas.dmtf.org/wbem/wsman/1/wsman/Heartbeat'

RESOURCE_URI_SUBSCRIPTION = 'http://schemas.microsoft.com/wbem/wsman/1/SubscriptionManager/Subscription'
RESOURCE_URI_EVENT_LOG = 'http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog'
RESOURCE_URI_FULL_DUPLEX = 'http://schemas.microsoft.com/wbem/wsman/1/wsman/FullDuplex'

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
        for name, value in globals().items():
            if name.startswith('ACTION_') and value == identifier:
                self.id = identifier
                return
        raise NameError(f'Invalid action identifier: {self.id}')

    def __eq__(self, other):
        return self.id == other

    def __repr__(self) -> str:
        return self.id

    def __str__(self) -> str:
        for name, value in globals().items():
            if name.startswith('ACTION_') and value == self.id:
                return name[7:]
        raise NameError(f'Invalid action identifier: {self.id}')


class ResourceURI:
    def __init__(self, identifier: str):
        for name, value in globals().items():
            if name.startswith('RESOURCE_URI_') and value == identifier:
                self.id = identifier
                return
        raise NameError(f'Invalid resource uri identifier: {self.id}')

    def __eq__(self, other):
        return self.id == other

    def __repr__(self) -> str:
        return self.id

    def __str__(self) -> str:
        for name, value in globals().items():
            if name.startswith('RESOURCE_URI_') and value == self.id:
                return name[13:]
        raise NameError(f'Invalid resource uri identifier: {self.id}')


class Envelope:
    def __init__(self, action: str, resource_uri: str or None, operation_id: str = None, message_id: str = None):
        self.action = Action(action) if action else None
        self.resource_uri = ResourceURI(resource_uri) if resource_uri else None
        self.operation_id = operation_id or f'uuid:{uuid.uuid4()}'
        self.id = message_id or f'uuid:{uuid.uuid4()}'
        self.sequence_id = 1

    @staticmethod
    def load(tree: ET.Element) -> Envelope:
        envelope = tree
        action = envelope.find('s:Header/a:Action', namespace)
        action = action.text.strip() if action is not None else None
        resource_uri = envelope.find('s:Header/w:ResourceURI', namespace)
        resource_uri = resource_uri.text.strip() if resource_uri is not None else None
        message_id = envelope.find('s:Header/a:MessageID', namespace)
        message_id = message_id.text.strip() if message_id is not None else None
        operation_id = envelope.find('s:Header/p:OperationID', namespace)
        operation_id = operation_id.text.strip() if operation_id is not None else None

        if action == ACTION_ENUMERATE:
            return EnumerateSubscriptionEnvelope.load(tree)
        elif action == ACTION_ENUMERATE_RESPONSE:
            return EnumerateResponseEnvelope.load(tree)
        else:
            return Envelope(action, resource_uri, operation_id, message_id)

    def xml(self) -> ET.Element:
        pass

    def dump(self) -> str:
        return ET.tostring(self.xml(), encoding='unicode')

    def __repr__(self) -> str:
        return f'<Envelope {repr(self.id)} {{{repr(self.action)}, {repr(self.resource_uri)}}}>'

    def __str__(self) -> str:
        return f'<Envelope {str(self.id)} {{{str(self.action)}, {str(self.resource_uri)}}}>'


class EnumerateSubscriptionEnvelope(Envelope):
    def __init__(self, operation_id: str, locale: str, data_locale: str, session_id: str,
                 operation_timeout: float = 60, machine_id: str = None, message_id: str = None):
        super().__init__(ACTION_ENUMERATE, RESOURCE_URI_SUBSCRIPTION, operation_id, message_id)
        self.to = ADDRESS_ANONYMOUS
        self.machine_id = machine_id
        self.reply_to = ADDRESS_ANONYMOUS
        self.max_envelope_size = 512000
        self.locale = locale
        self.data_locale = data_locale
        self.session_id = session_id
        self.operation_timeout = operation_timeout
        self.enumerate_max_elements = 32000

    @staticmethod
    def load(tree: ET.Element) -> EnumerateSubscriptionEnvelope:
        envelope = tree

        resource_uri = envelope.find('s:Header/w:ResourceURI', namespace)
        resource_uri = resource_uri.text.strip() if resource_uri is not None else None
        action = envelope.find('s:Header/a:Action', namespace)
        action = action.text.strip() if action is not None else None
        message_id = envelope.find('s:Header/a:MessageID', namespace)
        message_id = message_id.text.strip() if message_id is not None else None
        operation_id = envelope.find('s:Header/p:OperationID', namespace)
        operation_id = operation_id.text.strip() if operation_id is not None else None

        to = envelope.find('s:Header/a:To', namespace)
        to = to.text.strip() if to is not None else None
        machine_id = envelope.find('s:Header/m:MachineID',
                                   {**namespace, 'm': 'http://schemas.microsoft.com/wbem/wsman/1/machineid'})
        machine_id = machine_id.text.strip() if machine_id is not None else None
        reply_to = envelope.find('s:Header/a:ReplyTo/a:Address', namespace)
        reply_to = reply_to.text.strip() if reply_to is not None else None
        max_envelope_size = envelope.find('s:Header/w:MaxEnvelopeSize', namespace)
        max_envelope_size = int(max_envelope_size.text.strip()) if max_envelope_size is not None else None
        locale = envelope.find('s:Header/w:Locale', namespace)
        locale = locale.get('{http://www.w3.org/XML/1998/namespace}lang') if locale is not None else None
        data_locale = envelope.find('s:Header/p:DataLocale', namespace)
        data_locale = data_locale.get('{http://www.w3.org/XML/1998/namespace}lang') if data_locale is not None else None
        session_id = envelope.find('s:Header/p:SessionId', namespace)
        session_id = session_id.text.strip() if session_id is not None else None
        sequence_id = envelope.find('s:Header/p:SequenceId', namespace)
        sequence_id = int(sequence_id.text.strip()) if sequence_id is not None else None
        operation_timeout = envelope.find('s:Header/w:OperationTimeout', namespace)
        operation_timeout = _get_time(operation_timeout.text.strip()) if operation_timeout is not None else None
        enumerate_max_elements = envelope.find('s:Body/n:Enumerate/w:MaxElements', namespace)
        enumerate_max_elements = int(enumerate_max_elements.text.strip()) if enumerate_max_elements is not None else None

        if resource_uri != RESOURCE_URI_SUBSCRIPTION:
            raise AssertionError()
        if action != ACTION_ENUMERATE:
            raise AssertionError()

        envelope = EnumerateSubscriptionEnvelope(
            operation_id=operation_id,
            message_id=message_id,
            machine_id=machine_id,
            locale=locale,
            data_locale=data_locale,
            session_id=session_id,
            operation_timeout=operation_timeout,
        )
        envelope.to = to
        envelope.reply_to = reply_to
        envelope.max_envelope_size = max_envelope_size
        envelope.sequence_id = sequence_id
        envelope.enumerate_max_elements = enumerate_max_elements
        return envelope

    def xml(self) -> ET.Element:
        raise NotImplementedError()  # TODO EnumerateSubscription.xml() is needed for client

    def __repr__(self) -> str:
        return f'<EnumerateSubscription {repr(self.id)} {{{repr(self.machine_id)}, ' \
               f'Sess={repr(self.session_id)}, {repr(self.to)}}}>'

    def __str__(self) -> str:
        return f'<EnumerateSubscription {str(self.id)} {{{str(self.machine_id)}, ' \
               f'Sess={str(self.session_id)}, {str(self.to)}}}>'


class SubscriptionEnvelope(Envelope):
    def __init__(self, name: str, address: str, queries: List[Tuple[str, str]], issuer_thumbprints: List[str],
                 operation_id: str = None, message_id: str = None):
        super().__init__(ACTION_SUBSCRIBE, RESOURCE_URI_EVENT_LOG, operation_id, message_id)
        self.to = ADDRESS_ANONYMOUS
        self.reply_to = ADDRESS_ANONYMOUS
        self.max_envelope_size = 512000
        self.locale = 'en-US'
        self.data_locale = 'en-US'
        self.name = name
        self.compression = None  # None or 'SLDC'
        self.cdata = None
        self.content_format = 'RenderedText'  # RenderedText or Raw
        self.ignore_channel_error = None
        self.read_existing_events = False
        self.address = address
        self.reference = str(uuid.uuid4())
        self.heartbeat_sec = 3600.0
        self.issuer_thumbprints = issuer_thumbprints
        self.connection_retries = 5
        self.connection_retries_wait = 60.0
        self.max_time = 30.0
        self.content_encoding = 'UTF-8'
        self.bookmarks = False
        self.queries = queries
        self.query_id = 0

    def xml(self) -> ET.Element:
        envelope = ET.Element('s:Envelope', namespace_)

        header = ET.SubElement(envelope, 's:Header')
        to = ET.SubElement(header, 'a:To')
        to.text = str(self.to)
        resource_uri = ET.SubElement(header, 'w:ResourceURI')
        resource_uri.text = repr(self.resource_uri)
        reply_to = ET.SubElement(header, 'a:ReplyTo')
        address = ET.SubElement(reply_to, 'a:Address')
        address.text = str(self.reply_to)
        action = ET.SubElement(header, 'a:Action')
        action.text = repr(self.action)
        max_envelope_size = ET.SubElement(header, 'w:MaxEnvelopeSize')
        max_envelope_size.text = str(self.max_envelope_size)
        message_id = ET.SubElement(header, 'a:MessageID')
        message_id.text = str(self.id)
        locale = ET.SubElement(header, 'w:Locale')
        locale.set('xml:lang', str(self.locale))
        data_locale = ET.SubElement(header, 'p:DataLocale')
        data_locale.set('xml:lang', str(self.data_locale))
        operation_id = ET.SubElement(header, 'p:OperationID')
        operation_id.text = str(self.operation_id)
        sequence_id = ET.SubElement(header, 'p:SequenceId')
        sequence_id.text = str(self.sequence_id)

        option_set = ET.SubElement(header, 'w:OptionSet', {'xmlns:xsi': 'http://www.w3.org/2001/XMLSchema-instance'})
        subscription_name = ET.SubElement(option_set, 'w:Option')
        subscription_name.set('Name', 'SubscriptionName')
        subscription_name.text = str(self.name)
        if self.compression is not None:
            compression = ET.SubElement(option_set, 'w:Option')
            compression.set('Name', 'Compression')
            compression.text = str(self.compression)
        cdata = ET.SubElement(option_set, 'w:Option')
        cdata.set('Name', 'CDATA')
        if self.cdata is None:
            cdata.set('xsi:nil', 'true')
        else:
            raise NotImplementedError()
        content_format = ET.SubElement(option_set, 'w:Option')
        content_format.set('Name', 'ContentFormat')
        content_format.text = str(self.content_format)
        ignore_channel_error = ET.SubElement(option_set, 'w:Option')
        ignore_channel_error.set('Name', 'IgnoreChannelError')
        if self.ignore_channel_error is None:
            ignore_channel_error.set('xsi:nil', 'true')
        else:
            raise NotImplementedError()
        if self.read_existing_events:
            read_existing_events = ET.SubElement(option_set, 'w:Option')
            read_existing_events.set('Name', 'ReadExistingEvents')
            read_existing_events.text = 'true'

        body = ET.SubElement(envelope, 's:Body')
        subscribe = ET.SubElement(body, 'e:Subscribe')
        end_to = ET.SubElement(subscribe, 'e:EndTo')
        address = ET.SubElement(end_to, 'a:Address')
        address.text = str(self.address)
        reference_properties = ET.SubElement(end_to, 'a:ReferenceProperties')
        identifier = ET.SubElement(reference_properties, 'e:Identifier')
        identifier.text = str(self.reference)

        delivery = ET.SubElement(subscribe, 'e:Delivery')
        delivery.set('Mode', 'http://schemas.dmtf.org/wbem/wsman/1/wsman/Events')
        heartbeats = ET.SubElement(delivery, 'w:Heartbeats')
        heartbeats.text = f'PT{self.heartbeat_sec}S'
        notify_to = ET.SubElement(delivery, 'e:NotifyTo')
        address = ET.SubElement(notify_to, 'a:Address')
        address.text = str(self.address)
        reference_properties = ET.SubElement(notify_to, 'a:ReferenceProperties')
        identifier = ET.SubElement(reference_properties, 'e:Identifier')
        identifier.text = str(self.reference)

        policy = ET.SubElement(notify_to, 'c:Policy', {
            'xmlns:c': 'http://schemas.xmlsoap.org/ws/2002/12/policy',
            'xmlns:auth': 'http://schemas.microsoft.com/wbem/wsman/1/authentication'
        })
        exactly_one = ET.SubElement(policy, 'c:ExactlyOne')
        for issuer_thumbprint in self.issuer_thumbprints:
            match_all = ET.SubElement(exactly_one, 'c:All')
            auth = ET.SubElement(match_all, 'auth:Authentication')
            auth.set('Profile', 'http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual')
            client_cert = ET.SubElement(auth, 'auth:ClientCertificate')
            thumbprint = ET.SubElement(client_cert, 'auth:Thumbprint')
            thumbprint.set('Role', 'issuer')
            thumbprint.text = str(issuer_thumbprint).upper()

        connection_retry = ET.SubElement(delivery, 'w:ConnectionRetry')
        connection_retry.set('Total', str(self.connection_retries))
        connection_retry.text = f'PT{self.connection_retries_wait}S'
        max_time = ET.SubElement(delivery, 'w:MaxTime')
        max_time.text = f'PT{self.max_time}S'
        max_envelope_size = ET.SubElement(delivery, 'w:MaxEnvelopeSize')
        locale = ET.SubElement(delivery, 'w:Locale')
        locale.set('xml:lang', self.locale)
        data_locale = ET.SubElement(delivery, 'p:DataLocale')
        data_locale.set('xml:lang', self.data_locale)
        max_envelope_size.set('Policy', 'Notify')
        max_envelope_size.text = str(self.max_envelope_size)
        content_encoding = ET.SubElement(delivery, 'w:ContentEncoding')
        content_encoding.text = str(self.content_encoding)

        filter = ET.SubElement(subscribe, 'w:Filter')
        filter.set('Dialect', 'http://schemas.microsoft.com/win/2004/08/events/eventquery')
        query_list = ET.SubElement(filter, 'QueryList')
        query = ET.SubElement(query_list, 'Query')
        query.set('Id', str(self.query_id))
        for q in self.queries:
            elem = ET.SubElement(query, 'Select')
            elem.set('Path', q[0])
            elem.text = q[1]

        if self.bookmarks:
            ET.SubElement(subscribe, 'SendBookmarks')

        return envelope


class EnumerateResponseEnvelope(Envelope):
    def __init__(self, subscription: SubscriptionEnvelope, operation_id: str, relates_to: str, message_id: str = None):
        super().__init__(ACTION_ENUMERATE_RESPONSE, None, operation_id, message_id)
        self.to = ADDRESS_ANONYMOUS
        self.relates_to = relates_to
        self.subscription = subscription
        self.version = f'uuid:{subscription.reference}'

    @staticmethod
    def load(tree: ET.Element) -> Envelope:
        raise NotImplementedError()  # TODO EnumerateResponse.load() is needed for client

    def xml(self) -> ET.Element:
        envelope = ET.Element('s:Envelope', namespace_)

        header = ET.SubElement(envelope, 's:Header')
        action = ET.SubElement(header, 'a:Action')
        action.text = repr(self.action)
        message_id = ET.SubElement(header, 'a:MessageID')
        message_id.text = str(self.id)
        to = ET.SubElement(header, 'a:To')
        to.text = str(self.to)
        operation_id = ET.SubElement(header, 'p:OperationID')
        operation_id.text = str(self.operation_id)
        sequence_id = ET.SubElement(header, 'p:SequenceId')
        sequence_id.text = str(self.sequence_id)
        relates_to = ET.SubElement(header, 'a:RelatesTo')
        relates_to.text = str(self.relates_to)

        body = ET.SubElement(envelope, 's:Body')
        enumerate_response = ET.SubElement(body, 'n:EnumerateResponse')
        ET.SubElement(enumerate_response, 'n:EnumerationContext')
        items = ET.SubElement(enumerate_response, 'w:Items')
        ET.SubElement(enumerate_response, 'w:EndOfSequence')

        subscription = ET.SubElement(items, 'm:Subscription', {
            'xmlns:m': 'http://schemas.microsoft.com/wbem/wsman/1/subscription'
        })
        version = ET.SubElement(subscription, 'm:Version')
        version.text = str(self.version)
        subscription.append(self.subscription.xml())

        return envelope

    def __repr__(self) -> str:
        return f'<EnumerateResponse {{}}>'

    def __str__(self) -> str:
        return f'<EnumerateResponse {{}}>'


class HeartbeatEnvelope(Envelope):
    pass


class AckEnvelope(Envelope):
    pass


if __name__ == '__main__':
    env = EnumerateSubscriptionEnvelope.load(ET.parse('raw/01-client.raw.xml').getroot())
    print(env)
    print(env.operation_timeout)
    print(env.to)
    print(env.locale, env.data_locale)
