project(aspf-core)

file(GLOB HEADERS include/*)

add_library(aspf-core INTERFACE ${HEADERS})
target_include_directories(aspf-core INTERFACE include)
