cmake_minimum_required(VERSION 3.16)
project(forgevpn C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# Core library: networking/protocol modules shared by the daemon and by
# tests that need to exercise them directly (e.g. tun_test).
add_library(forgevpn_core STATIC
    src/tun.c
    src/udp.c
    src/config.c
    src/crypto.c
)
target_include_directories(forgevpn_core PUBLIC include ${SODIUM_INCLUDE_DIRS})
target_link_libraries(forgevpn_core PUBLIC ${SODIUM_LIBRARIES})
target_compile_options(forgevpn_core PUBLIC ${SODIUM_CFLAGS_OTHER})

add_executable(forgevpn src/main.c)
target_link_libraries(forgevpn PRIVATE forgevpn_core)

add_executable(forgevpn-keygen tools/keygen.c)
target_link_libraries(forgevpn-keygen PRIVATE forgevpn_core)

enable_testing()

add_executable(tun_test tests/tun_test.c)
target_link_libraries(tun_test PRIVATE forgevpn_core)
add_test(NAME tun_test COMMAND tun_test)

add_executable(udp_test tests/udp_test.c)
target_link_libraries(udp_test PRIVATE forgevpn_core)
add_test(NAME udp_test COMMAND udp_test)

add_executable(config_test tests/config_test.c)
target_link_libraries(config_test PRIVATE forgevpn_core)
add_test(NAME config_test COMMAND config_test)

add_executable(crypto_test tests/crypto_test.c)
target_link_libraries(crypto_test PRIVATE forgevpn_core)
add_test(NAME crypto_test COMMAND crypto_test)

add_test(
    NAME smoke_test
    COMMAND ${CMAKE_SOURCE_DIR}/tests/smoke_test.sh $<TARGET_FILE:forgevpn>
)
