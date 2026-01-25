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
- [ ] Replace HANDLE with OwnedHandle to get rid of CloseHandle
- [ ] Simplify syntax, get rid of the need to type unnecessary things, such as "handle" etc.
- [x] ~~Get rid of unnecessary searches for additional processes~~
- [ ] More tests
- [ ] Docs
- [ ] And something else, i forgot

## 🚀How to add to a project:
```
cargo add --git https://github.com/partoftheworlD/gamehack_librs
```
## 📖How to use:

```rust
use gamehack_librs::{close_handle, find_process, read, utils::find_signature};

fn main() {
    match find_process("hitman3.exe") {
        Ok(process) => {
            // Get address and size of exe
            let base = process.module_list.first().unwrap().module_addr;
            let base_size = process.module_list.first().unwrap().module_size;

            let mut ptr_phitman_vft = 0usize;
            // Reading multilevel pointer:
            // ["hitman3.exe"+022BAF18] + 0x18
            read(
                process.handle,
                base + 0x022BAF18,
                &[0x18],
                &raw mut ptr_phitman_vft,
            );

            println!("ptr_phitman_vft: {ptr_phitman_vft:X}");

            // Find signature
            // .text:00000001402D9A0F 48 8D 05 **7A B9 A6 01**       lea     rax, ??_7ZHitman5@@6B@_0 ; const ZHitman5::`vftable'
            // .text:00000001402D9A16 48 89 41 18                    mov     [rcx+18h], rax
            // .text:00000001402D9A1A 49 BF 00 00 00 00 00 00        mov     r15, 4000000000000000h
            // .text:00000001402D9A1A 00 40

            let phitman_vft = find_signature(
                process.handle,
                base,
                base_size,
                b"\x48\x8D\x05\x7A\xB9\xA6\x01\x48\x89\x41\x18\x49\xBF",
                "xxx????xxxxxx",
            )
            .unwrap() + 3;

            let mut pointer = 0u32;

            // Reading an address without offsets to get RVA of ZHitman5::`vftable':
            // phitman_vft + 3
            read(process.handle, phitman_vft, &[], &raw mut pointer);

            println!(
                "Sign found: {:X} -> {:X}",
                phitman_vft,
                phitman_vft + size_of::<u32>() + pointer as usize
            );

            // OUTPUT:
            // Hitman VFT: 141D45390
            // Sign found: 1402D9A12 -> 141D45390

            // You must close handle until this library starts using OwnedHandle
            close_handle(process.handle);
        }
        Err(why) => println!("{why}"),
    }
}
```
