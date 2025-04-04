# MinHook-Detours

A hooking library with a [MinHook](https://github.com/TsudaKageyu/minhook)-like
API and a [Detours](https://github.com/microsoft/Detours)-like implementation,
with support for the x86, x64, and ARM64 platforms.

The main motivation for creating it is having the MinHook API, which I
personally find more user-friendly, while also adding ARM64 support, which
MinHook lacks.


## SlimDetours

MinHook-Detours uses [SlimDetours](https://github.com/KNSoft/KNSoft.SlimDetours)
under the hood. SlimDetours is an improved hooking library based on [Microsoft
Detours](https://github.com/microsoft/Detours). It includes several critical
fixes, such as avoiding deadlocks that may occur with the original Detours
library. In addition, it incorporates multiple improvements [I
submitted](https://github.com/KNSoft/KNSoft.SlimDetours/issues?q=is%3Apr%20author%3Am417z%20)
to add missing functionality and bring it closer to feature parity with MinHook.
