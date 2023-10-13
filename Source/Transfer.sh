
staging="$1"
stable="$2"
paths="$3"

echo 'Staging:'
echo "${staging}"
echo 'Stable:'
echo "${stable}"
echo 'Paths:'
echo "${paths}"


echo "${paths}" | xargs git checkout "${stable}" --


echo "Checked out stable files"

git status

echo "Removing deleted files"

echo "${paths}" | xargs     \
    git diff-tree           \
        --name-only         \
        -r                  \
        --diff-filter=D     \
        "${staging}"        \
        "${stable}"         \
        --                  \
| rm -rf {}

echo "Removed deleted files"
