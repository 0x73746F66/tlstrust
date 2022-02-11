from tlstrust import context
from .ccadb import __version__ as ccadb_ver
from .linux import __version__ as linux_ver
from .java import __version__ as java_ver
from .certifi import __version__ as certifi_ver
from .android_2_2 import __version__ as android_2_2_ver
from .android_2_3 import __version__ as android_2_3_ver
from .android_3 import __version__ as android_3_ver
from .android_4 import __version__ as android_4_ver
from .android_4_4 import __version__ as android_4_4_ver
from .android_7 import __version__ as android_7_ver
from .android_8 import __version__ as android_8_ver
from .android_9 import __version__ as android_9_ver
from .android_10 import __version__ as android_10_ver
from .android_11 import __version__ as android_11_ver
from .android_12 import __version__ as android_12_ver
from .android_latest import __version__ as android_latest_ver


__module__ = 'tlstrust.stores'
VERSIONS = {
    context.SOURCE_CCADB: ccadb_ver,
    context.SOURCE_JAVA: java_ver,
    context.SOURCE_ANDROID: android_latest_ver,
    context.SOURCE_LINUX: linux_ver,
    context.SOURCE_CERTIFI: certifi_ver,
    context.PLATFORM_ANDROID2_2: android_2_2_ver,
    context.PLATFORM_ANDROID2_3: android_2_3_ver,
    context.PLATFORM_ANDROID3: android_3_ver,
    context.PLATFORM_ANDROID4: android_4_ver,
    context.PLATFORM_ANDROID4_4: android_4_4_ver,
    context.PLATFORM_ANDROID7: android_7_ver,
    context.PLATFORM_ANDROID8: android_8_ver,
    context.PLATFORM_ANDROID9: android_9_ver,
    context.PLATFORM_ANDROID10: android_10_ver,
    context.PLATFORM_ANDROID11: android_11_ver,
    context.PLATFORM_ANDROID12: android_12_ver,
}
