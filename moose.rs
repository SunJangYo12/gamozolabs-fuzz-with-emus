#![feature(asm)]

#[no_mangle]
pub fn moose() {
    unsafe { asm!("int3"); }
}
