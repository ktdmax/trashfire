cmake_minimum_required(VERSION 3.20)
project(murrayd-signal VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# BUG-0001: Compiler hardening flags disabled — no stack protector, no ASLR, no fortify (CWE-693, CVSS 5.0, BEST_PRACTICE, Tier 5)
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2")
# set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie -Wl,-z,relro,-z,now")

find_package(Boost 1.80 REQUIRED COMPONENTS system)
find_package(Threads REQUIRED)

# BUG-0002: Using FetchContent for nlohmann_json without pinning hash — supply chain risk (CWE-829, CVSS 6.5, MEDIUM, Tier 2)
include(FetchContent)
FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG master
)
FetchContent_MakeAvailable(nlohmann_json)

add_executable(murrayd-signal
  src/main.cpp
  src/broker/broker.cpp
  src/broker/session.cpp
  src/broker/topic_manager.cpp
  src/protocol/parser.cpp
  src/protocol/serializer.cpp
  src/storage/db.cpp
  src/storage/timeseries.cpp
  src/api/http_server.cpp
  src/api/query_handler.cpp
)

target_include_directories(murrayd-signal PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${Boost_INCLUDE_DIRS}
)

target_link_libraries(murrayd-signal PRIVATE
  Boost::system
  Threads::Threads
  nlohmann_json::nlohmann_json
  sqlite3
)

# BUG-0003: Debug symbols included in release build, information disclosure (CWE-215, CVSS 3.0, LOW, Tier 4)
target_compile_options(murrayd-signal PRIVATE -g -O0)

install(TARGETS murrayd-signal DESTINATION bin)
