project(aspf-xdp C)

file(GLOB HEADERS include/*)
file(GLOB SOURCES lib/*)

add_custom_command(
        OUTPUT include/vmlinux.h
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        COMMAND ${CMAKE_COMMAND} -E make_directory include
        COMMAND bpftool btf dump file /sys/kernel/btf/vmlinux format c > "include/vmlinux.h"
        DEPENDS /sys/kernel/btf/vmlinux
        COMMENT "Generating vmlinux.h"
        VERBATIM
)
list(APPEND HEADERS include/vmlinux.h)

add_library(aspf-xdp OBJECT ${HEADERS} ${SOURCES})
target_include_directories(aspf-xdp PUBLIC include)
target_compile_options(aspf-xdp PUBLIC -target bpf -O2 -g)
target_link_libraries(aspf-xdp PUBLIC aspf-core)
