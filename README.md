# Rust library for creating basic external cheats
For now that's enough to complete my money cheats for GTA 5/RP/FiveM and silent aim in HITMAN WOA

## ✅Supported:
- Read/Write into memory
- Signature scanner
- Access processes modules by name

## 📝Plan to-Do:
- [x] ~~Dll enumeration~~
- [ ] Replace HANDLE with OwnedHandle to get rid of CloseHandle or Implement Drop for HANDLE
- [ ] Simplify syntax, get rid of the need to type unnecessary things, such as "handle" etc.
- [x] ~~Get rid of unnecessary searches for additional processes~~
- [ ] More tests
- [x] ~~Docs~~
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
            if let Some(exe) = process.module_list.get("hitman3.exe") {
                let base = exe.module_addr;
                let base_size = exe.module_size;

                let mut ptr_phitman_vft = 0usize;

                // Reading multilevel pointer:
                // ["hitman3.exe"+022BAF18] + 0x18

                read(
                    process.handle,
                    base + 0x022BAF18,
                    &[0x18],
                    &raw mut ptr_phitman_vft,
                );
                println!("Hitman VFT: {ptr_phitman_vft:X}");

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
                .unwrap();

                let mut pointer = 0u32;
                let byte_shift = 3;

                // Reading an address without offsets to get RVA of ZHitman5::`vftable':
                // phitman_vft + 3

                read(
                    process.handle,
                    phitman_vft + byte_shift,
                    &[],
                    &raw mut pointer,
                );

                // OUTPUT:
                // Hitman VFT: 141D45390
                // Sign found: 1402D9A12 -> 141D45390

                println!(
                    "Sign found: {:X} -> {:X}",
                    phitman_vft + byte_shift,
                    phitman_vft + byte_shift + size_of_val(&pointer) + pointer as usize
                );
            }

            // You must close handle until this library starts using OwnedHandle
            close_handle(process.handle);
        }
        Err(why) => println!("{why}"),
    }
}
```
