from dissononce.processing.impl.handshakestate import HandshakeState
from dissononce.extras.processing.handshakestate_guarded import GuardedHandshakeState
from dissononce.extras.processing.handshakestate_switchable import SwitchableHandshakeState
from dissononce.processing.handshakepatterns.interactive.IK import IKHandshakePattern
from dissononce.processing.handshakepatterns.interactive.XX import XXHandshakePattern
from dissononce.processing.modifiers.fallback import FallbackPatternModifier
from dissononce.processing.impl.cipherstate import CipherState
from dissononce.cipher.aesgcm import AESGCMCipher
from dissononce.hash.sha256 import SHA256Hash
from dissononce.dh.keypair import KeyPair
from dissononce.dh.x25519.public import PublicKey
from dissononce.dh.private import PrivateKey
from dissononce.dh.x25519.x25519 import X25519DH
from dissononce.extras.dh.dangerous.dh_nogen import NoGenDH
from dissononce.exceptions.decrypt import DecryptFailedException
from google.protobuf.message import DecodeError

from .config.client import ClientConfig
from .dissononce_extras.processing.symmetricstate_wa import WASymmetricState
from .proto import wa20_pb2, wa_pb2
from .certman.certman import CertMan
from .exceptions.new_rs_exception import NewRemoteStaticException
from .structs.publickey import PublicKey
from .util.byte import ByteUtil
from.exceptions.handshake_failed_exception import HandshakeFailedException

import logging

logger = logging.getLogger(__name__)


class WAHandshake(object):
    def __init__(self, version_major, version_minor):
        self._prologue = b"WA" + bytearray([version_major, version_minor])
        self._handshakestate = None  # type: HandshakeState | None

    async def perform(self, client_config, stream, s, rs=None, e=None):
        """
        :param client_config:
        :type client_config:
        :param stream:
        :type stream:
        :param s:
        :type s: consonance.structs.keypair.KeyPair
        :param rs:
        :type rs: consonance.structs.publickey.PublicKey | None
        :type e: consonance.structs.keypair.KeyPair | None
        :return:
        :rtype:
        """
        logger.debug("perform(client_config=%s, stream=%s, s=%s, rs=%s, e=%s)" % (
            client_config, stream, s, rs, e
        ))
        dh = X25519DH()
        if e is not None:
            dh = NoGenDH(dh, PrivateKey(e.private.data))
        self._handshakestate = SwitchableHandshakeState(
            GuardedHandshakeState(
                HandshakeState(
                    WASymmetricState(
                        CipherState(
                            AESGCMCipher()
                        ),
                        SHA256Hash()
                    ),
                    dh
                )
            )
        )  # type: SwitchableHandshakeState
        dissononce_s = KeyPair(
            PublicKey(s.public.data),
            PrivateKey(s.private.data)
        )
        dissononce_rs = PublicKey(rs.data) if rs else None
        client_payload = self._create_full_payload(client_config)
        logger.debug("Create client_payload=%s" % client_payload)
        try:
            if rs is not None:
                try:
                    cipherstatepair = await self._start_handshake_ik(stream, client_payload, dissononce_s, dissononce_rs)
                except NewRemoteStaticException as ex:
                   cipherstatepair = await self._switch_handshake_xxfallback(stream, dissononce_s, client_payload, ex.server_hello)
            else:
                cipherstatepair = await self._start_handshake_xx(stream, client_payload, dissononce_s)

            return cipherstatepair
        except DecryptFailedException as e:
            logger.exception(e)
            raise HandshakeFailedException(e)
        except DecodeError as e:
            logger.exception(e)
            raise HandshakeFailedException(e)

    @property
    def rs(self):
        return PublicKey(self._handshakestate.rs.data) if self._handshakestate.rs else None

    async def _start_handshake_xx(self, stream, client_payload, s):
        """
        :param stream:
        :type stream: SegmentedStream
        :param client_payload:
        :type client_payload:
        :param s:
        :type s: KeyPair
        :return:
        :rtype:
        """
        self._handshakestate.initialize(
            handshake_pattern=XXHandshakePattern(),
            initiator=True,
            prologue=self._prologue,
            s=s
        )
        ephemeral_public = bytearray()
        self._handshakestate.write_message(b'', ephemeral_public)
        handshakemessage = wa_pb2.HandshakeMessage()
        handshakemessage.clientHello.ephemeral = bytes(ephemeral_public)
        await stream.write_segment(handshakemessage.SerializeToString(), self._prologue)

        incoming_handshakemessage = wa_pb2.HandshakeMessage()
        incoming_handshakemessage.ParseFromString(await stream.read_segment())

        if not incoming_handshakemessage.HasField("serverHello"):
            raise ValueError("Handshake message does not contain server hello!")

        server_hello = incoming_handshakemessage.serverHello
        
        payload_buffer = bytearray()
        self._handshakestate.read_message(
            server_hello.ephemeral + server_hello.static + server_hello.payload, payload_buffer
        )
        certman = CertMan()

        if certman.is_valid(self._handshakestate.rs, bytes(payload_buffer)):
            logger.debug("cert is valid")
        else:
            logger.error("cert is not valid")

        message_buffer = bytearray()
        cipherpair = self._handshakestate.write_message(client_payload.SerializeToString(), message_buffer)

        static, payload = ByteUtil.split(bytes(message_buffer), 48, len(message_buffer) - 48)
        client_finish = wa20_pb2.HandshakeMessage.ClientFinish()
        client_finish.static = static
        client_finish.payload = payload
        outgoing_handshakemessage = wa20_pb2.HandshakeMessage()
        outgoing_handshakemessage.client_finish.MergeFrom(client_finish)
        await stream.write_segment(outgoing_handshakemessage.SerializeToString())

        return cipherpair

    async def _start_handshake_ik(self, stream, client_payload, s, rs):
        """
        :param stream:
        :type stream: SegmentedStream
        :param s:
        :type s: KeyPair
        :param rs:
        :type rs: PublicKey
        :return:
        :rtype:
        """
        self._handshakestate.initialize(
            handshake_pattern=IKHandshakePattern(),
            initiator=True,
            prologue=self._prologue,
            s=s,
            rs=rs
        )
        message_buffer = bytearray()
        self._handshakestate.write_message(client_payload.SerializeToString(), message_buffer)
        ephemeral_public, static_public, payload = ByteUtil.split(bytes(message_buffer), 32, 48, len(message_buffer) - 32 + 48)
        handshakemessage = wa20_pb2.HandshakeMessage()
        client_hello = wa20_pb2.HandshakeMessage.ClientHello()

        client_hello.ephemeral = ephemeral_public
        client_hello.static = static_public
        client_hello.payload = payload
        handshakemessage.client_hello.MergeFrom(client_hello)

        await stream.write_segment(handshakemessage.SerializeToString())

        incoming_handshakemessage = wa20_pb2.HandshakeMessage()
        incoming_handshakemessage.ParseFromString(await stream.read_segment())

        if not incoming_handshakemessage.HasField("server_hello"):
            raise HandshakeFailedException("Handshake message does not contain server hello!")

        server_hello = incoming_handshakemessage.server_hello

        if server_hello.HasField("static"):
            raise NewRemoteStaticException(server_hello)

        payload_buffer = bytearray()
        return self._handshakestate.read_message(
            server_hello.ephemeral + server_hello.static + server_hello.payload, payload_buffer
        )

    async def _switch_handshake_xxfallback(self, stream, s, client_payload, server_hello):
        """
        :param handshake_pattern:
        :type handshake_pattern: HandshakePattern
        :param stream:
        :type stream: SegmentedStream
        :param s:
        :type s: KeyPair
        :param e:
        :type e: KeyPair
        :param client_payload:
        :type client_payload:
        :param server_hello:
        :type server_hello:
        :return:
        :rtype: tuple(CipherState,CipherState)
        """
        self._handshakestate.switch(
                handshake_pattern=FallbackPatternModifier().modify(XXHandshakePattern()),
                initiator=True,
                prologue=self._prologue,
                s=s
            )
        payload_buffer = bytearray()
        self._handshakestate.read_message(server_hello.ephemeral + server_hello.static + server_hello.payload, payload_buffer)
        certman = CertMan()
        if certman.is_valid(self._handshakestate.rs, bytes(payload_buffer)):
            logger.debug("cert is valid")
        else:
            logger.error("cert is not valid")

        message_buffer = bytearray()

        cipherpair = self._handshakestate.write_message(client_payload.SerializeToString(), message_buffer)

        static, payload = ByteUtil.split(bytes(message_buffer), 48, len(message_buffer) - 48)
        client_finish = wa20_pb2.HandshakeMessage.ClientFinish()
        client_finish.static = static
        client_finish.payload = payload
        outgoing_handshakemessage = wa20_pb2.HandshakeMessage()
        outgoing_handshakemessage.client_finish.MergeFrom(client_finish)
        await stream.write_segment(outgoing_handshakemessage.SerializeToString())

        return cipherpair

    def _create_full_payload(self, client_config:ClientConfig):
        """
        :param client_config:
        :type client_config: ClientConfig
        :return:
        :rtype: wa_pb2.ClientPayload
        """
        client_payload = wa_pb2.ClientPayload()

        client_payload.passive = client_config.passive
        user_agent = client_payload.userAgent
        user_agent.platform = client_config.userAgent.platform
        user_agent.appVersion.primary = client_config.userAgent.appVersion['primary']
        user_agent.appVersion.secondary = client_config.userAgent.appVersion['secondary']
        user_agent.appVersion.tertiary = client_config.userAgent.appVersion['tertiary']
        user_agent.mcc = client_config.userAgent.mcc
        user_agent.mnc = client_config.userAgent.mnc
        user_agent.osVersion = client_config.userAgent.osVersion
        user_agent.manufacturer = client_config.userAgent.manufacturer
        user_agent.device = client_config.userAgent.device
        user_agent.osBuildNumber = client_config.userAgent.osBuildNumber
        user_agent.releaseChannel = client_config.userAgent.releaseChannel
        user_agent.localeLanguageIso6391 = client_config.userAgent.localeLanguageIso6391
        user_agent.localeCountryIso31661Alpha2 = client_config.userAgent.localeCountryIso31661Alpha2

        client_payload.webInfo.webSubPlatform = client_config.webInfo['webSubPlatform']
        client_payload.connectType = client_config.connectType
        client_payload.connectReason = client_config.connectReason

        device_pairing_data = client_payload.devicePairingData
        device_pairing_data.eRegid = client_config.devicePairingData.eRegid
        device_pairing_data.eKeytype = client_config.devicePairingData.eKeytype
        device_pairing_data.eIdent = client_config.devicePairingData.eIdent
        device_pairing_data.eSkeyId = client_config.devicePairingData.eSkeyId
        device_pairing_data.eSkeyVal = client_config.devicePairingData.eSkeyVal
        device_pairing_data.eSkeySig = client_config.devicePairingData.eSkeySig
        device_pairing_data.buildHash = client_config.devicePairingData.buildHash

        device_props = wa_pb2.DeviceProps()
        client_device_props = client_config.devicePairingData.deviceProps
        device_props.os = client_device_props.os
        device_props.version.primary = client_device_props.version['primary']
        device_props.version.secondary = client_device_props.version['secondary']
        device_props.version.tertiary = client_device_props.version['tertiary']
        device_props.platformType = client_device_props.platformType
        device_props.requireFullSync = client_device_props.requireFullSync

        device_pairing_data.deviceProps = device_props.SerializeToString()

        return client_payload
