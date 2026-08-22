from __future__ import annotations

import pytest

from biopgp.localization import set_language


@pytest.fixture(autouse=True)
def reset_interface_language() -> None:
    set_language("ru")
    yield
    set_language("ru")
