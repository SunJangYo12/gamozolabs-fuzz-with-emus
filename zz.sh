
while [ 1 ]; do
    read -p "commit: " msg
    git add src/main.rs
    git commit -m "$msg"
done
