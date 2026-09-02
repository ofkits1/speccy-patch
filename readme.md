# Speccy Patch

A lightweight DLL that removes trial limitations from Speccy system information tool.

## What It Does

- Removes the registration/trial nag screen
- Unlocks full functionality without a license key
- Exe stays untouched — patches applied in-memory at runtime

## How It Works

The DLL masquerades as `version.dll` and sits alongside `Speccy.exe`. On launch it:

1. Forwards all `version.dll` API calls to the real system DLL
2. Resolves kernel32 functions via hash-based lookup (no IAT traces)
3. Decrypts the real DLL path and loads it from `System32`
4. Scans the host EXE image and applies targeted binary patches

## Installation

1. Drop `version.dll` (compiled from this source) in the install folder
2. Run `Speccy.exe` — that's it

## Notes

- Built for **Speccy x64** versions. Other builds may not work.
- AV may flag the DLL — false positives are common with in-memory patching tools.
- For educational purposes only.

## Disclaimer

This project is for **educational and research purposes only**. Use at your own risk. The author is not responsible for any misuse or damage.

---

Cracked by **github.com/ofkits1**