import hashlib
from consonance_web.proto import wa_pb2
from axolotl.util.keyhelper import KeyHelper


class ClientConfig():
    class UserAgent():
        platform = wa_pb2.ClientPayload.UserAgent.Platform.WEB
        appVersion = {'primary':2, 'secondary':2230, 'tertiary':10}
        mcc = '000'
        mnc = '000'
        osVersion = '0.1.0'
        manufacturer = ''
        device = 'Desktop'
        osBuildNumber = '0.1.0'
        releaseChannel = wa_pb2.ClientPayload.UserAgent.ReleaseChannel.RELEASE
        localeLanguageIso6391 = 'en'
        localeCountryIso31661Alpha2 = 'en'
    
    class DevicePairingData():
        def __init__(self, eRegid, eKeytype, eIdent, eSkeyId, eSkeyVal, eSkeySig, buildHash, deviceProps):
            self.eRegid = eRegid
            self.eKeytype = eKeytype
            self.eIdent = eIdent
            self.eSkeyId = eSkeyId
            self.eSkeyVal = eSkeyVal
            self.eSkeySig = eSkeySig
            self.buildHash = buildHash
            self.deviceProps = deviceProps
    
    class DeviceProps():
        os = 'Linux'
        version = {'primary':5, 'secondary':10, 'tertiary':61}
        platformType = wa_pb2.DeviceProps.PlatformType.UNKNOWN
        requireFullSync = False
        
    passive = False
    userAgent = UserAgent()
    webInfo = {'webSubPlatform': wa_pb2.ClientPayload.WebInfo.WebSubPlatform.WEB_BROWSER}
    connectType = wa_pb2.ClientPayload.ConnectType.WIFI_UNKNOWN
    connectReason = wa_pb2.ClientPayload.ConnectReason.USER_ACTIVATED
    devicePairingData = None #Will be defined on class init
    deviceProps = DeviceProps()

    def __init__(self, eRegid, eKeytype, eIdent, eSkeyId, eSkeyVal, eSkeySig, buildHash) -> None:
        self.devicePairingData = self.DevicePairingData(eRegid, eKeytype, eIdent, eSkeyId, eSkeyVal,
                                                        eSkeySig, buildHash, self.deviceProps)        


def get_client_payload(eRegid, eKeytype, eIdent, eSkeyId, eSkeyVal, 
                    eSkeySig, buildHash) -> wa_pb2.ClientPayload:
    client_payload = wa_pb2.ClientPayload()

    client_payload.passive = False

    user_agent = client_payload.userAgent
    user_agent.platform = wa_pb2.ClientPayload.UserAgent.Platform.WEB
    user_agent.appVersion.primary = 2
    user_agent.appVersion.secondary = 2230
    user_agent.appVersion.tertiary = 10
    user_agent.mcc = '000'
    user_agent.mnc = '000'
    user_agent.osVersion = '0.1.0'
    user_agent.manufacturer = ''
    user_agent.device = 'Desktop'
    user_agent.osBuildNumber = '0.1.0'
    user_agent.releaseChannel = wa_pb2.ClientPayload.UserAgent.ReleaseChannel.RELEASE
    user_agent.localeLanguageIso6391 = 'en'
    user_agent.localeCountryIso31661Alpha2 = 'en'

    client_payload.webInfo.webSubPlatform = wa_pb2.ClientPayload.WebInfo.WebSubPlatform.WEB_BROWSER
    client_payload.connectType = wa_pb2.ClientPayload.ConnectType.WIFI_UNKNOWN
    client_payload.connectReason = wa_pb2.ClientPayload.ConnectReason.USER_ACTIVATED

    device_pairing_data = client_payload.devicePairingData
    device_pairing_data.eRegid = eRegid
    device_pairing_data.eKeytype = eKeytype
    device_pairing_data.eIdent = eIdent
    device_pairing_data.eSkeyId = eSkeyId
    device_pairing_data.eSkeyVal = eSkeyVal
    device_pairing_data.eSkeySig = eSkeySig
    device_pairing_data.buildHash = buildHash

    device_props = wa_pb2.DeviceProps()
    device_props.os = 'Linux'
    device_props.version.primary = 5
    device_props.version.secondary = 10
    device_props.version.tertiary = 61
    device_props.platformType = wa_pb2.DeviceProps.PlatformType.UNKNOWN
    device_props.requireFullSync = False

    device_pairing_data.deviceProps = device_props.SerializeToString()

    return client_payload


def get_new_client(wa_version) -> ClientConfig:
    '''
    Generate the client data needed for registration and login.
    '''

    identityKeyPair = KeyHelper.generateIdentityKeyPair()
    registrationId  = KeyHelper.generateRegistrationId()
    #preKeys         = KeyHelper.generatePreKeys(1, 100)
    #lastResortKey   = KeyHelper.generateLastResortKey()
    signedPreKey    = KeyHelper.generateSignedPreKey(identityKeyPair, 5)
    wa_version_hash = hashlib.md5(wa_version.encode("ascii"))

    eKeyType = 5

    return ClientConfig(registrationId.to_bytes(4, "big"), 
                                    eKeyType.to_bytes(1, "big"),
                                    identityKeyPair.getPublicKey().getPublicKey().getPublicKey(),
                                    signedPreKey.getId().to_bytes(3, "big"), 
                                    signedPreKey.getKeyPair().getPublicKey().getPublicKey(),
                                    signedPreKey.getSignature(),
                                    wa_version_hash.digest())
