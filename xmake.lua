add_rules("mode.release", "mode.debug")

set_languages("c++23")

add_requires("mbedtls 3.6.1")
add_requires("gtest 1.15.2", { optional = true })

target("tinyhttps")
    set_kind("static")
    set_version("0.1.0")
    add_files("src/*.cppm", { public = true, install = true })
    add_packages("mbedtls", { public = true })
    set_policy("build.c++.modules", true)

target("tinyhttps_tests")
    set_kind("binary")
    set_default(false)
    add_files("tests/*.cpp")
    add_files("src/*.cppm")
    add_packages("mbedtls", "gtest")
    set_policy("build.c++.modules", true)
