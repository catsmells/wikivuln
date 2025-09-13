from builtins import __build_class__
C = __build_class__(lambda: None, "🤯")
C.hello = lambda: print(f'Hello from {C.__name__}!')
globals().update({C.__name__:C})