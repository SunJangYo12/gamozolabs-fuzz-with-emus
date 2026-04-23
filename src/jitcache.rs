use crate::mmu::VirtAddr;

#[cfg(target_os="windows")]
pub fn alloc_rwx(size: usize) -> &'static mut [u8] {
    extern {
        fn VirtualAlloc(lpAddress: *const u8, dwSize: usize,
                        flAllocationType: u32, flProtect: u32) -> *mut u8;
    }

    unsafe {
        const PAGE_EXECUTE_READWRITE: u32 = 0x40;

        const MEM_COMMIT:  u32 = 0x00001000;
        const MEM_RESERVE: u32 = 0x00002000;

        let ret = VirtualAlloc(0 as *const _, size, MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
        assert!(!ret.is_null());

        std::slice::from_raw_parts_mut(ret, size)
    }
}

#[cfg(target_os="linux")]
pub fn alloc_rwx(size: usize) -> &'static mut [u8] {
    extern {
        fn mmap(addr: *mut u8, length: usize, prot: i32, flags: i32, fd: i32,
                offset: usize) -> *mut u8;
    }

    unsafe {
        // Alloc RWX and MAP_PRIVATE | MAP_ANON
        let ret = mmap(0 as *mut u8, size, 7, 34, -1, 0);
        assert!(!ret.is_null());

        std::slice::from_raw_parts_mut(ret, size)
    }
}

/// A cache which stores cached JIT blocks and tranlation tables to them
struct JitCache {
    /// A vector which contains the addresses of JIT code for the
    /// corresponding guest virtual address.
    ///
    /// Ex. jit_addr = jitcache.blocks[Guest Virtual Address / 4];
    ///
    /// An entry which is a zero indicates the block has not yet
    /// been translated.
    ///
    /// The blocks are referenced by the guest virtual address divided by 4
    /// because all RISCV-V instructions are 4 bytes (for the non-compressed variant)
    blocks: Box<[usize]>,

    /// The raw JIT RWX backing
    jit: &'static mut [u8],

    /// Number of bytes in use in `jit`
    inuse: usize,
}

impl JitCache {
    /// Allocates a new `JitCache` which is capable of handling up to
    /// `max_guest_addr` in executable code.
    pub fn new(max_guest_addr: VirtAddr) -> Self {
        JitCache {
            // Allocate a zeroed out block cache   
            blocks:
                vec![0usize; (max_guest_addr.0 + 3) / 4].into_boxed_slice(),
            jit: alloc_rwx(16 * 1024 * 1024),
            inuse: 0,
        }
    }
}
