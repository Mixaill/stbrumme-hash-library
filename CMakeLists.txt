cmake_minimum_required(VERSION 3.0)
project(stbrumme-hash-library)

set(SRCS
 src/sha256.cpp
)

set(HDRS
 src/hmac.h
 src/sha256.h
)

add_library(stbrumme-hash-library ${SRCS} ${HDRS})
target_include_directories(stbrumme-hash-library PUBLIC "src")

enable_testing()

add_executable(test_hmac_sha256 "tests/test_hmac_sha256.cpp")
target_link_libraries(test_hmac_sha256 PRIVATE stbrumme-hash-library)

add_test(test_hmac_sha256_1 test_hmac_sha256 1)
add_test(test_hmac_sha256_2 test_hmac_sha256 2)
add_test(test_hmac_sha256_3 test_hmac_sha256 3)


