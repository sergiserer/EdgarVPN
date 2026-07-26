cmake_minimum_required(VERSION 3.16)
project(edgarvpn C)

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
add_library(edgarvpn_core STATIC
    src/tun.c
    src/udp.c
    src/config.c
    src/crypto.c
    src/session.c
    src/routing.c
    src/log.c
)
target_include_directories(edgarvpn_core PUBLIC include ${SODIUM_INCLUDE_DIRS})
target_link_libraries(edgarvpn_core PUBLIC ${SODIUM_LIBRARIES})
target_compile_options(edgarvpn_core PUBLIC ${SODIUM_CFLAGS_OTHER})

add_executable(edgarvpn src/main.c)
target_link_libraries(edgarvpn PRIVATE edgarvpn_core)

add_executable(edgarvpn-keygen tools/keygen.c)
target_link_libraries(edgarvpn-keygen PRIVATE edgarvpn_core)

enable_testing()

add_executable(tun_test tests/tun_test.c)
target_link_libraries(tun_test PRIVATE edgarvpn_core)
add_test(NAME tun_test COMMAND tun_test)

add_executable(udp_test tests/udp_test.c)
target_link_libraries(udp_test PRIVATE edgarvpn_core)
add_test(NAME udp_test COMMAND udp_test)

add_executable(config_test tests/config_test.c)
target_link_libraries(config_test PRIVATE edgarvpn_core)
add_test(NAME config_test COMMAND config_test)

add_executable(crypto_test tests/crypto_test.c)
target_link_libraries(crypto_test PRIVATE edgarvpn_core)
add_test(NAME crypto_test COMMAND crypto_test)

add_executable(session_test tests/session_test.c)
target_link_libraries(session_test PRIVATE edgarvpn_core)
add_test(NAME session_test COMMAND session_test)

add_executable(routing_test tests/routing_test.c)
target_link_libraries(routing_test PRIVATE edgarvpn_core)
add_test(NAME routing_test COMMAND routing_test)

add_executable(log_test tests/log_test.c)
target_link_libraries(log_test PRIVATE edgarvpn_core)
add_test(NAME log_test COMMAND log_test)

add_test(
    NAME smoke_test
    COMMAND ${CMAKE_SOURCE_DIR}/tests/smoke_test.sh $<TARGET_FILE:edgarvpn>
)
