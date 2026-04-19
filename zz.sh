
while [ 1 ]; do
    read -p "commit: " msg
    git add src/main.rs
    git add src/primitive.rs
    git add src/mmu.rs
    git add src/emulator.rs

    git commit -m "$msg"
done
