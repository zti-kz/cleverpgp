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
    """Return two readable words, a symbol and four random digits."""

    words = secrets.choice(_ADJECTIVES) + secrets.choice(_NOUNS)
    number = 1000 + secrets.randbelow(9000)
    password = words + secrets.choice(_SYMBOLS) + str(number)
    # Even the shortest available pair reaches the application's 12-character
    # minimum; keep this invariant explicit if the vocabulary changes later.
    if len(password) < 12:
        password += secrets.choice(string.ascii_uppercase)
    return password


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
