from __future__ import annotations

from cleverpgp.ui.container_dialog import (
    GIBIBYTE,
    MEBIBYTE,
    ContainerCreationDialog,
)


def test_container_default_name_is_derived_from_capacity() -> None:
    assert ContainerCreationDialog._capacity_name(128 * MEBIBYTE) == "CPGP_128MB"
    assert ContainerCreationDialog._capacity_name(2 * GIBIBYTE) == "CPGP_2GB"
