
staging="$1"
stable="$2"
paths="$3"

echo 'Staging:'
echo "${staging}"
echo 'Stable:'
echo "${stable}"
echo 'Paths:'
echo "${paths}"


"${paths}" | xargs git checkout "${stable}" -- {}


git status


"${paths}" | xargs rm -rf $(    \
    git diff-tree               \
        --name-only             \
        -r                      \
        --diff-filter=D         \
        "${staging}"            \
        "${stable}              \
        -- {}                   \
)
