from importlib import __import__
MOD_NAMES = ['🤯','🤒','😪','😎']
MODS = [__import__(name=m, fromlist=[m]) for m in MOD_NAMES]
globals().update({m.__name__: m for m in MODS})

for emoji in MOD_NAMES:
    globals().get(emoji).__getattribute__(emoji).hello()