"""
SEP Firmware Loader — Binary Ninja plugin.

Registers the SEPFirmwareView binary view type so that Binary Ninja will
offer to open *.bin / *.im4p files that contain raw 64-bit SEP firmware.
"""

from .sep_view import SEPFirmwareView

SEPFirmwareView.register()
