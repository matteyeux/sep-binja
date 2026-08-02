from .sep_view import SEPFirmwareView
from . import sep_api

SEPFirmwareView.register()

# Let other plugins find the loader without importing this package, whose name
# is whatever folder it was installed under.
sep_api.publish()

try:
    from .triage_view import SEPTriageViewType

    SEPTriageViewType.register()
except Exception:
    # Headless Binary Ninja: importing binaryninjaui raises
    # UIPluginInHeadlessError, which is not an ImportError. Catching only that
    # left this traceback in the log of every headless run — and would have
    # skipped anything registered after it.
    pass
