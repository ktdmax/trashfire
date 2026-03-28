cmake_minimum_required(VERSION 3.16)
project(lechuck-crypt C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

# BUG-0001: No stack protector flags — allows stack buffer overflow exploitation (CWE-119, CVSS 9.8, CRITICAL, Tier 1)
# BUG-0002: No ASLR/PIE flags — binary loads at predictable address (CWE-119, CVSS 7.5, HIGH, Tier 2)
# BUG-0003: No FORTIFY_SOURCE — missing compile-time buffer overflow checks (CWE-120, CVSS 5.0, MEDIUM, Tier 3)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -O2")

# BUG-0004: Debug symbols in release build leak internal structure info (CWE-215, CVSS 3.5, LOW, Tier 4)
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -g")

find_package(OpenSSL REQUIRED)

add_executable(lechuck-vpnd
    src/main.c
    src/tunnel.c
    src/crypto.c
    src/packet.c
    src/config.c
    src/logging.c
    src/daemon.c
    src/auth.c
    src/routing.c
)

target_include_directories(lechuck-vpnd PRIVATE include)
target_link_libraries(lechuck-vpnd OpenSSL::SSL OpenSSL::Crypto)

# BUG-0005: Installation with world-readable permissions on binary (CWE-732, CVSS 5.3, MEDIUM, Tier 3)
install(TARGETS lechuck-vpnd DESTINATION /usr/local/sbin
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                GROUP_READ GROUP_EXECUTE
                WORLD_READ WORLD_EXECUTE)

install(FILES vpn.conf.example DESTINATION /etc/lechuck/
    PERMISSIONS OWNER_READ OWNER_WRITE
                GROUP_READ
                WORLD_READ)
