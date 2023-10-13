
staging="$1"
stable="$2"
paths="$3"


"${paths}" | xargs git checkout stable -- {}


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
