#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Perm(u8);

/// An isolated memory space
struct Mmu {
    // Block of memory for this address space
    // Offset 0 corresponds to address 0 in the guest address space
    memory: Vec<u8>,

    // Holds the permission bytes for the corresponding byte in memory
    permissions: Vec<Perm>,
}

impl Mmu {
    // Create a new memory space which can hold `size` bytes
    pub fn new(size: usize) -> Self {
        Mmu {
            memory:      vec![0; size],
            permissions: vec![Perm(0); size],
        }
    }
}

/// All the state of the emulated system
struct Emulator {
    /// Memory for the emulator
    memory: Mmu,
}

fn main() {
    println!("Hello, world!");
}
