#!/usr/bin/env python3

# owinec - Open Windows Event Collector
# NT LAN Manager (NTLM) Authentication Protocol (NLMP) implementation
# Lorenz Stechauner, 2020

from __future__ import annotations
from typing import Tuple, Iterator
import datetime
import struct
import base64

CHARSET_OEM = 'cp437'
CHARSET_UNICODE = 'utf16'

NEGOTIATE_MESSAGE = 0x1
CHALLENGE_MESSAGE = 0x2
AUTHENTICATE_MESSAGE = 0x3

NTLMSSP_NEGOTIATE_56 = 0x80000000
NTLMSSP_NEGOTIATE_KEY_EXCH = 0x40000000
NTLMSSP_NEGOTIATE_128 = 0x20000000
NTLMSSP_NEGOTIATE_VERSION = 0x02000000
NTLMSSP_NEGOTIATE_TARGET_INFO = 0x00800000
NTLMSSP_REQUEST_NON_NT_SESSION_KEY = 0x00400000
NTLMSSP_NEGOTIATE_IDENTIFY = 0x00100000
NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
NTLMSSP_TARGET_TYPE_SERVER = 0x00020000
NTLMSSP_TARGET_TYPE_DOMAIN = 0x00010000
NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x00008000
NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 0x00002000
NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED = 0x00001000
NTLMSSP_ANONYMOUS = 0x00000800
NTLMSSP_NEGOTIATE_NTLM = 0x00000200
NTLMSSP_NEGOTIATE_LM_KEY = 0x00000080
NTLMSSP_NEGOTIATE_DATAGRAM = 0x00000040
NTLMSSP_NEGOTIATE_SEAL = 0x00000020
NTLMSSP_NEGOTIATE_SIGN = 0x00000010
NTLMSSP_REQUEST_TARGET = 0x00000004
NTLM_NEGOTIATE_OEM = 0x00000002
NTLMSSP_NEGOTIATE_UNICODE = 0x00000001

MsvAvEOL = 0x0000
MsvAvNbComputerName = 0x0001
MsvAvNbDomainName = 0x0002
MsvAvDnsComputerName = 0x0003
MsvAvDnsDomainName = 0x0004
MsvAvDnsTreeName = 0x0005
MsvAvFlags = 0x0006
MsvAvTimestamp = 0x0007
MsvAvSingleHost = 0x0008
MsvAvTargetName = 0x0009
MsvAvChannelBindings = 0x000A

MsvAvFlags_ACCOUNT_AUTH_CONSTRAINT = 0x00000001
MsvAvFlags_MIC_PROVIDED = 0x00000002
MsvAvFlags_SPN_UNTRUSTED = 0x00000004


def _unpack_filetime(data: bytes) -> datetime.datetime:
    """
    >>> _unpack_filetime(b'\\xd0\\x8c\\xdd\\xb8\\xec\\x02\\xd6\\x01')
    datetime.datetime(2020, 3, 25, 21, 31, 19, 107298)
    """
    return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=struct.unpack('<Q', data)[0] / 10)


def _pack_filetime(timestamp: datetime.datetime) -> bytes:
    """
    >>> _pack_filetime(datetime.datetime(2020, 3, 25, 21, 31, 19, 107298))
    b'\\xd0\\x8c\\xdd\\xb8\\xec\\x02\\xd6\\x01'
    """
    return struct.pack('<Q', int((timestamp - datetime.datetime(1601, 1, 1)).total_seconds() * 10_000_000))


class Version:
    # TODO Version doctests

    def __init__(self, major_version: int, minor_version: int, product_build: int, ntlm_revision: int = 0x0F):
        self.major_version = major_version
        self.minor_version = minor_version
        self.product_build = product_build
        self.ntlm_revision = ntlm_revision

    @staticmethod
    def decode(data: bytes) -> Version:
        major_version, minor_verion, product_build, reserved, ntlm_revision = struct.unpack('<BBH3sB', data)
        return Version(major_version, minor_verion, product_build, ntlm_revision)

    def encode(self) -> bytes:
        return struct.pack('<BBH3sB', self.major_version, self.minor_version, self.product_build, bytes(3),
                           self.ntlm_revision)

    def __repr__(self) -> str:
        return f'<Version {{{self.major_version}.{self.minor_version}-{self.product_build}, {self.ntlm_revision}}}>'

    def __str__(self) -> str:
        return self.__repr__()


class NegotiateFlags:
    """
    >>> NegotiateFlags()
    <NegotiateFlags {}>
    >>> NegotiateFlags(0xE20882B7)
    <NegotiateFlags {NTLMSSP_NEGOTIATE_56, NTLMSSP_NEGOTIATE_KEY_EXCH, NTLMSSP_NEGOTIATE_128, NTLMSSP_NEGOTIATE_VERSION, NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY, NTLMSSP_NEGOTIATE_ALWAYS_SIGN, NTLMSSP_NEGOTIATE_NTLM, NTLMSSP_NEGOTIATE_LM_KEY, NTLMSSP_NEGOTIATE_SEAL, NTLMSSP_NEGOTIATE_SIGN, NTLMSSP_REQUEST_TARGET, NTLM_NEGOTIATE_OEM, NTLMSSP_NEGOTIATE_UNICODE}>
    >>> NegotiateFlags(0xE28A8235)
    <NegotiateFlags {NTLMSSP_NEGOTIATE_56, NTLMSSP_NEGOTIATE_KEY_EXCH, NTLMSSP_NEGOTIATE_128, NTLMSSP_NEGOTIATE_VERSION, NTLMSSP_NEGOTIATE_TARGET_INFO, NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY, NTLMSSP_TARGET_TYPE_SERVER, NTLMSSP_NEGOTIATE_ALWAYS_SIGN, NTLMSSP_NEGOTIATE_NTLM, NTLMSSP_NEGOTIATE_SEAL, NTLMSSP_NEGOTIATE_SIGN, NTLMSSP_REQUEST_TARGET, NTLMSSP_NEGOTIATE_UNICODE}>
    >>> flags = NegotiateFlags(0x1)
    >>> flags[NTLMSSP_NEGOTIATE_UNICODE]
    True
    >>> flags[NTLMSSP_NEGOTIATE_UNICODE] = False
    >>> flags[NTLMSSP_NEGOTIATE_UNICODE]
    False
    >>> flags[NTLMSSP_NEGOTIATE_VERSION] = True
    >>> flags[NTLMSSP_NEGOTIATE_VERSION]
    True
    >>> NTLMSSP_NEGOTIATE_UNICODE in flags
    False
    >>> NTLMSSP_NEGOTIATE_VERSION in flags
    True
    >>> int(NegotiateFlags())
    0
    >>> int(NegotiateFlags(0xE20882B7))
    3792208567
    >>> int(NegotiateFlags(0xE28A8235))
    3800728117
    """

    def __init__(self, negotiate_flags: int = 0):
        self._flags = negotiate_flags

    def __setitem__(self, key: int, value: bool):
        if value:
            self._flags |= key
        else:
            self._flags &= ~key

    def __getitem__(self, item: int) -> bool:
        return self._flags & item != 0

    def __contains__(self, item: int) -> bool:
        return self[item]

    def __int__(self) -> int:
        return self._flags

    def __repr__(self) -> str:
        flags_str = []
        for name, value in globals().items():
            if (name.startswith('NTLM_') or name.startswith('NTLMSSP_')) and value in self:
                flags_str.append(name)
        return f'<NegotiateFlags {{{", ".join(flags_str)}}}>'

    def __str__(self) -> str:
        return self.__repr__()


class AVPair:
    # TODO AVPair doctests

    def __init__(self, av_id: int, value):
        if av_id not in (MsvAvEOL, MsvAvNbComputerName, MsvAvNbDomainName, MsvAvDnsComputerName, MsvAvDnsDomainName,
                         MsvAvDnsTreeName, MsvAvFlags, MsvAvTimestamp, MsvAvSingleHost, MsvAvTargetName,
                         MsvAvChannelBindings):
            raise AssertionError('Invalid AVPair id')
        self.id = av_id
        self.value = value

    @staticmethod
    def decode(data: bytes, charset: str) -> Tuple[AVPair, int]:
        av_id, av_len = struct.unpack('<HH', data[:4])
        if av_id == MsvAvEOL:
            if av_len != 0:
                raise AssertionError('Invalid NTLM AVPair (type MsvAvEOL): length has to be 0')
            return AVPair(av_id, None), 4
        elif av_id in (MsvAvNbComputerName, MsvAvNbDomainName, MsvAvDnsComputerName, MsvAvDnsDomainName,
                       MsvAvDnsTreeName, MsvAvTargetName):
            return AVPair(av_id, data[4:4 + av_len].decode(charset)), 4 + av_len
        elif av_id == MsvAvFlags:
            if av_len != 4:
                raise AssertionError('Invaild NTLM AVPair (type MsvAvFlags): length has to be 32 bit')
            return AVPair(av_id, struct.unpack('<I', data[4:8])[0]), 8
        elif av_id == MsvAvTimestamp:
            if av_len != 8:
                raise AssertionError('Invalid NTLM AVPair (type MsvAvTimestamp): length has to be 64 bit')
            return AVPair(av_id, _unpack_filetime(data[4:12])), 12
        elif av_id in (MsvAvSingleHost, MsvAvChannelBindings):
            return AVPair(av_id, data[4:4 + av_len]), 4 + av_len
        else:
            raise AssertionError('Invalid NTLM AVPair: unexpected error')

    def encode(self, charset: str) -> bytes:
        if self.id == MsvAvEOL:
            return struct.pack('<HH', self.id, 0)
        elif self.id in (MsvAvNbComputerName, MsvAvNbDomainName, MsvAvDnsComputerName, MsvAvDnsDomainName,
                         MsvAvDnsTreeName, MsvAvTargetName):
            value_encoded = self.value.encode(charset)
            return struct.pack('<HH', self.id, len(value_encoded)) + value_encoded
        elif self.id == MsvAvFlags:
            return struct.pack('<HHI', self.id, 4, self.value)
        elif self.id == MsvAvTimestamp:
            return struct.pack('<HH', self.id, 8) + _pack_filetime(self.value)
        elif self.id in (MsvAvSingleHost, MsvAvChannelBindings):
            return struct.pack('<HH', self.id, len(self.value)) + self.value
        else:
            raise ReferenceError('Invalid NTLM AVPair id')

    def __repr__(self) -> str:
        for name, value in globals().items():
            if name.startswith('MsvAv') and '_' not in name and value == self.id:
                return f'{name}: {repr(self.value)}'
        raise ReferenceError('Invalid NTLM AVPair id')

    def __str__(self) -> str:
        return self.__repr__()


class AVPairList:
    # TODO AVPairList doctests

    def __init__(self):
        self._pairs = []

    @staticmethod
    def decode(data: bytes, charset: str) -> AVPairList:
        av_pair_list = AVPairList()
        while True:
            av, av_len = AVPair.decode(data, charset)
            data = data[av_len:]
            if av.id == MsvAvEOL:
                return av_pair_list
            else:
                av_pair_list._pairs.append(av)

    def encode(self, charset: str) -> bytes:
        return b''.join([av.encode(charset) for av in self])

    def __iter__(self) -> Iterator[AVPair]:
        return self._pairs.__iter__()

    def __getitem__(self, item: int) -> object:
        for av in self:
            if av.id == item:
                return av.value
        raise NameError('Attribute in AVPair not found')

    def __setitem__(self, key: int, value):
        for av in self:
            if av.id == key:
                av.value = value
                return
        self._pairs.append(AVPair(key, value))

    def __contains__(self, item: int) -> bool:
        for av in self:
            if av.id == item:
                return True
        return False

    def __repr__(self) -> str:
        return f'<AVPairList {{{", ".join([str(av) for av in self])}}}>'

    def __str__(self) -> str:
        return self.__repr__()


class Message:
    def __init__(self, msg_type: int):
        if msg_type not in (NEGOTIATE_MESSAGE, CHALLENGE_MESSAGE, AUTHENTICATE_MESSAGE):
            raise AssertionError('Invalid NTLM message type: invalid message type')
        self.version = Version(10, 0, 0)
        self.flags = NegotiateFlags()
        self.type = msg_type

    @property
    def charset(self) -> str:
        if NTLMSSP_NEGOTIATE_UNICODE in self.flags:
            return CHARSET_UNICODE
        elif NTLM_NEGOTIATE_OEM in self.flags:
            return CHARSET_OEM
        else:
            raise AssertionError('Invalid charset flags in NTLM message')

    @staticmethod
    def decode(data: bytes) -> Message:
        if not data.startswith(b'NTLMSSP\0'):
            raise AssertionError('Invalid NTLM message: invalid signature')
        msg_type, = struct.unpack('<I', data[8:12])
        if msg_type == NEGOTIATE_MESSAGE:
            return NegotiateMessage.decode(data)
        elif msg_type == CHALLENGE_MESSAGE:
            raise NotImplementedError()  # TODO reference ChallengeMessage
        elif msg_type == AUTHENTICATE_MESSAGE:
            raise NotImplementedError()  # TODO reference AuthenticateMessage
        else:
            raise NotImplementedError('Unexpected error')

    def encode(self) -> bytes:
        pass

    def __repr__(self) -> str:
        return f'<Message {{{repr(self.type)}, {repr(self.version)}, {repr(self.flags)}}}>'

    def __str__(self) -> str:
        return self.__repr__()


class NegotiateMessage(Message):
    """
    >>> NegotiateMessage.decode(base64.b64decode('TlRMTVNTUAABAAAAl4II4gAAAAAAAAAAAAAAAAAAAAAKALpHAAAADw=='))
    <NegotiateMessage {*@*, <NegotiateFlags {NTLMSSP_NEGOTIATE_56, NTLMSSP_NEGOTIATE_KEY_EXCH, NTLMSSP_NEGOTIATE_128, NTLMSSP_NEGOTIATE_VERSION, NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY, NTLMSSP_NEGOTIATE_ALWAYS_SIGN, NTLMSSP_NEGOTIATE_NTLM, NTLMSSP_NEGOTIATE_LM_KEY, NTLMSSP_NEGOTIATE_SIGN, NTLMSSP_REQUEST_TARGET, NTLM_NEGOTIATE_OEM, NTLMSSP_NEGOTIATE_UNICODE}>, <Version {10.0-18362, 15}>}>
    """

    def __init__(self, workstation: str or None, domain_name: str or None):
        super().__init__(NEGOTIATE_MESSAGE)
        self.domain_name = domain_name
        self.workstation = workstation

    @staticmethod
    def decode(data: bytes) -> NegotiateMessage:
        if not data.startswith(b'NTLMSSP\0'):
            raise AssertionError('Invalid NTLM message: invalid signature')
        msg_type, negotiate_flags, domain_name_len, domain_name_max_len, domain_name_offset, workstation_len, \
            workstation_max_len, workstation_offset, version = struct.unpack('<IIHHIHHI8s', data[8:40])
        msg = NegotiateMessage(None, None)
        msg.flags = NegotiateFlags(negotiate_flags)
        if NTLMSSP_NEGOTIATE_VERSION in msg.flags:
            msg.version = Version.decode(version)
        else:
            msg.version = None
        if NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED in msg.flags:
            msg.domain_name = data[domain_name_offset:domain_name_offset + domain_name_len].decode(msg.charset)
        if NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED in msg.flags:
            msg.workstation = data[workstation_offset:workstation_offset + workstation_offset].decode(msg.charset)
        return msg

    def encode(self) -> bytes:
        pass  # TODO encode NegotiateMessage

    def __repr__(self) -> str:
        return f'<NegotiateMessage {{{str(self.workstation or "*")}@{str(self.domain_name or "*")}, ' \
               f'{repr(self.flags)}, {repr(self.version)}}}>'

