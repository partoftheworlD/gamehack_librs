# Rust library for creating basic external cheats
For now that's enough to complete my money cheats for GTA 5/RP/FiveM and silent aim in HITMAN WOA

## ✅Supported:
- Read/Write into memory
- Signature scanner

```rust
    let sign = b"\x48\x8D\x05\x7A\xB9\xA6\x01\x48\x89\x41\x18\x49\xBF\x00\x00\x00\x00\x00\x00";
    let mask = "xxx????xxxxxxxxxxxx";

    let address = find_signature(handle, process.base_addr, process.base_size, sign, mask);
```

## 📝Plan to-Do:
- [x] ~~Dll enumeration~~
- [ ] Simplify syntax, get rid of the need to type unnecessary things, such as "handle" etc.
- [x] ~~Get rid of unnecessary searches for additional processes~~
- [ ] More tests
- [ ] Docs
- [ ] And something else, i forgot

## How to add to a project:
```
cargo add --git https://github.com/partoftheworlD/gamehack_librs
```
