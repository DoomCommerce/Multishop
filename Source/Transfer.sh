

IFS='\n' read -r -a array <<< "$2"

git checkout $1 --                  \
    templates                       \
    snippets                        \
    sections                        \
    assets                          \
    layout/password.liquid          \
    config/settings_schema.json     \
    ':!templates/**/*.json'         \
    ':!templates/*.json'            \
    ':!*/pickystory-*'              \
    ':!*/pagefly.*'                 \
    ':!*/pagefly-*'                 \
    ':!*/*.pf-*'                    \
    ':!*/pf-*'
