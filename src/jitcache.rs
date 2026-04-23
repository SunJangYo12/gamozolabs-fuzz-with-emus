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
}

impl JitCache {
    /// Allocates a new `JitCache` which is capable of handling up to
    /// `max_guest_addr` in executable code.
    pub fn new(max_guest_addr: VirtAddr) -> Self {
        JitCache {
            // Allocate a zeroed out block cache   
            blocks:
                vec![0usize; (max_guest_addr.0 + 3) / 4].into_boxed_slice(),
        }
    }
}
