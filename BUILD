go_library(
    name = "sri",
    srcs = ["sri.go"],
)

go_test(
    name = "sri_test",
    srcs = ["sri_test.go"],
    deps = [
        ":sri",
        ":testify",
    ],
)

go_get(
    name = "testify",
    get = "github.com/stretchr/testify/assert",
    revision = "v1.4.0",
    deps = [
        ":spew",
        ":yaml",
        ":difflib",
    ],
)

go_get(
    name = "spew",
    get = "github.com/davecgh/go-spew/spew",
    revision = "v1.1.1",
)

go_get(
    name = "difflib",
    get = "github.com/pmezard/go-difflib/difflib",
    revision = "v1.0.0",
)

go_get(
    name = "yaml",
    get = "gopkg.in/yaml.v2",
    revision = "v2.2.8",
)
