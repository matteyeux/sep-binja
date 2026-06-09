from .sep_view import SEPFirmwareView

SEPFirmwareView.register()

try:
    from .triage_view import SEPTriageViewType

    SEPTriageViewType.register()
except ImportError:
    # Headless Binary Ninja — no UI, skip the triage view
    pass
