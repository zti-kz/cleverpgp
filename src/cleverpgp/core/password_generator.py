from __future__ import annotations

import secrets
import string


_ADJECTIVES = (
    "Amber",
    "Brave",
    "Bright",
    "Calm",
    "Clear",
    "Clever",
    "Cool",
    "Cosmic",
    "Crystal",
    "Daring",
    "Deep",
    "Emerald",
    "Gentle",
    "Golden",
    "Grand",
    "Happy",
    "Hidden",
    "Keen",
    "Lively",
    "Lunar",
    "Merry",
    "Mighty",
    "Noble",
    "Quiet",
    "Rapid",
    "Royal",
    "Silver",
    "Solar",
    "Swift",
    "Vivid",
    "Warm",
    "Wise",
)

_NOUNS = (
    "Apple",
    "Atlas",
    "Badger",
    "Bay",
    "Beacon",
    "Birch",
    "Bison",
    "Bridge",
    "Brook",
    "Canyon",
    "Cedar",
    "Cloud",
    "Comet",
    "Coral",
    "Dawn",
    "Delta",
    "Eagle",
    "Elm",
    "Falcon",
    "Field",
    "Forest",
    "Fox",
    "Garden",
    "Grove",
    "Harbor",
    "Hawk",
    "Hill",
    "Island",
    "Jade",
    "Lake",
    "Leaf",
    "Lemon",
    "Maple",
    "Meadow",
    "Mint",
    "Moon",
    "Ocean",
    "Olive",
    "Orbit",
    "Otter",
    "Panda",
    "Peak",
    "Pearl",
    "Pine",
    "Quartz",
    "Rain",
    "Reef",
    "River",
    "Robin",
    "Rock",
    "Rose",
    "Sage",
    "Sky",
    "Spruce",
    "Star",
    "Stone",
    "Storm",
    "Summit",
    "Tiger",
    "Valley",
    "Wave",
    "Willow",
    "Wolf",
    "Zenith",
)

_SYMBOLS = "!@#$%&*?"


def generate_memorable_password() -> str:
    """Return a roughly 60-bit structured passphrase made for memorisation."""

    compounds = [
        secrets.choice(_ADJECTIVES) + secrets.choice(_NOUNS)
        for _ in range(4)
    ]
    number = 1000 + secrets.randbelow(9000)
    return "-".join(compounds) + secrets.choice(_SYMBOLS) + str(number)


def generate_random_password(length: int = 24) -> str:
    """Return a high-entropy password containing every major character class."""

    if length < 16:
        raise ValueError("Random passwords must contain at least 16 characters.")
    groups = (string.ascii_lowercase, string.ascii_uppercase, string.digits, _SYMBOLS)
    characters = [secrets.choice(group) for group in groups]
    alphabet = "".join(groups)
    characters.extend(secrets.choice(alphabet) for _ in range(length - len(characters)))
    secrets.SystemRandom().shuffle(characters)
    return "".join(characters)
