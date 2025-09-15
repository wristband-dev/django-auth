from typing import Any, Callable


def wristband_auth_required(view_func: Callable[..., Any]) -> Callable[..., Any]:
    """
    Decorator to mark function-based views as requiring Wristband authentication.

    Usage:
        @wristband_auth_required
        def my_view(request):
            return render(request, 'template.html')
    """
    view_func.wristband_auth_required = True  # type: ignore[attr-defined]
    return view_func
