
while [ 1 ]; do
    read -p "commit: " msg
    git add src/main.rs
    git add src/primitive.rs
    git add src/mmu.rs
    git add src/emulator.rs
    git add src/jitcache.rs
    git add zz.sh
    git add README
    git add test-jit/Makefile
    git add test-jit/test.rs
    git add test-jit/test.c
    git add test-jit/test.cpp

    git commit -m "$msg"
done
