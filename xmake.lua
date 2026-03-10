add_rules("mode.release", "mode.debug")

set_languages("c++23")

add_requires("mbedtls 3.6.1")

target("tinyhttps")
    set_kind("static")
    set_version("0.1.0")
    add_files("src/*.cppm", { public = true, install = true })
    add_packages("mbedtls", { public = true })
    set_policy("build.c++.modules", true)
