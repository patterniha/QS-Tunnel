[app]

title = QS Tunnel
package.name = qstunnel
package.domain = org.qstunnel

source.dir = .
source.include_exts = py,json

version = 1.0

requirements = python3,kivy,aiohttp

icon.filename = %(source.dir)s/icon.png

orientation = portrait

fullscreen = 0

# Android
android.permissions = android.permission.INTERNET, android.permission.POST_NOTIFICATIONS, android.permission.FOREGROUND_SERVICE, android.permission.WAKE_LOCK, android.permission.ACCESS_NETWORK_STATE, android.permission.RECEIVE_BOOT_COMPLETED, android.permission.CHANGE_WIFI_MULTICAST_STATE, android.permission.ACCESS_WIFI_STATE, android.permission.CHANGE_NETWORK_STATE, android.permission.CHANGE_WIFI_STATE

android.api = 34
android.minapi = 21
android.ndk_api = 21

android.archs = arm64-v8a

android.allow_backup = True

[buildozer]

log_level = 2

warn_on_root = 1
