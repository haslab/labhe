cmake_minimum_required (VERSION 2.6)
project (labhe)

enable_testing()

set(KECCAK_TARGET "generic64")

include_directories(include KeccakCodePackage/bin/${KECCAK_TARGET}/libkeccak.a.headers )

find_path(GMP_INCLUDE_DIR NAMES gmp.h)
find_library(GMP_LIBRARIES NAMES gmp libgmp)

add_library(
  labhe
  STATIC 
 
  src/bench/bench.c
  src/bhjl/bhjl.c
  src/bhjl/bhjl_gen.c
  src/labhe/labhe.c
  src/labhe/labhe_gen.c
  src/prf/prf.c
)
target_link_libraries(labhe ${GMP_LIBRARIES} ${CMAKE_SOURCE_DIR}/KeccakCodePackage/bin/${KECCAK_TARGET}/libkeccak.a)

add_executable(prf_test test/prf_test)
target_link_libraries(prf_test labhe)

add_executable(bhjl_test test/bhjl_test)
target_link_libraries(bhjl_test labhe)

add_executable(labhe_test test/labhe_test)
target_link_libraries(labhe_test labhe)

add_test(
  NAME prf_test 
  COMMAND prf_test
)

add_test(
  NAME bhjl_test 
  COMMAND bhjl_test
)

add_test(
  NAME labhe_test 
  COMMAND labhe_test
)