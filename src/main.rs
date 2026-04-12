const PERM_READ:  u8 = 1 << 0;
const PERM_WRITE: u8 = 1 << 1;
const PERM_EXEC:  u8 = 1 << 2;
const PERM_RAW:   u8 = 1 << 3;

/// A permissions byte which corresponds to a memory byte and defines
/// the permissions it has
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Perm(u8);

/// A guest virtual address
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct VirtAddr(usize);

/// An isolated memory space
struct Mmu {
    // Block of memory for this address space
    // Offset 0 corresponds to address 0 in the guest address space
    memory: Vec<u8>,

    // Holds the permission bytes for the corresponding byte in memory
    permissions: Vec<Perm>,

    /// Current base address of the next allocation
    cur_alc: VirtAddr,
}

impl Mmu {
    // Create a new memory space which can hold `size` bytes
    pub fn new(size: usize) -> Self {
        Mmu {
            memory:      vec![0; size], //buat 0 sebanyak size
            permissions: vec![Perm(0); size],
            cur_alc:     VirtAddr(0x10000),
        }
    }
    /// Allocate a region of memory as RW in the address space
    pub fn allocate(&mut self, size: usize) -> Option<VirtAddr> {
        // 16-byte align the allocation
        let align_size = (size + 0xf) & !0xf;

        // Get the current allocation base
        let base = self.cur_alc;

        // Cannot allocate
        if base.0 >= self.memory.len() {
            return None
        }

        // Update the allocation size
        self.cur_alc = VirtAddr(self.cur_alc.0.checked_add(align_size)?);

        // Could not satisfy allocation without going OOM
        if self.cur_alc.0 > self.memory.len() {
            return None;
        }

        // Mark the memory as un-initialized and writable
        self.set_permissions(base, size, Perm(PERM_RAW | PERM_WRITE));

        Some(base)
    }

    /// Apply permissions to a region of memory
    pub fn set_permissions(&mut self, addr: VirtAddr, size: usize,
                            perm: Perm) -> Option<()> {
        // Apply permissions
        self.permissions.get_mut(addr.0..addr.0.checked_add(size)?)?
            .iter_mut().for_each(|x| *x = perm);
        Some(())
    }

    /// write the bytes from `buf` into `addr`
    pub fn write_from(&mut self, addr: VirtAddr, buf: &[u8]) -> Option<()> {
        self.memory.get_mut(addr.0..addr.0.checked_add(buf.len())?)?
            .copy_from_slice(buf);
        Some(())
    }        

    pub fn read_into(&mut self, addr: VirtAddr, buf: &mut [u8]) -> Option<()> {
        buf.copy_from_slice(
            self.memory.get_mut(addr.0..addr.0.checked_add(buf.len())?)?);
        Some(())
    }        
}

/// All the state of the emulated system
struct Emulator {
    /// Memory for the emulator
    pub memory: Mmu,
}

impl Emulator {
    /// Creates a new emulator with `size` bytes of memory
    pub fn new(size: usize) -> Self {
        Emulator {
            memory: Mmu::new(size),
        }
    }
}

fn main() {
    let mut emu = Emulator::new(1024 * 1024); // 1MB

    let tmp = emu.memory.allocate(4096).unwrap();
    emu.memory.write_from(tmp, b"asdf").unwrap();

    let mut bytes = [0u8; 32];
    emu.memory.read_into(tmp, &mut bytes).unwrap();

    print!("{:x?}\n", bytes);
}
