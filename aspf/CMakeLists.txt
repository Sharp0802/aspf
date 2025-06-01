project(aspf C)

file(GLOB HEADERS include/*)
file(GLOB SOURCES lib/*)

add_executable(aspf ${HEADERS} ${SOURCES})
target_include_directories(aspf PUBLIC include)
target_link_libraries(aspf PUBLIC aspf-core bpf)
add_dependencies(aspf aspf-xdp-post)

add_custom_target(aspf-xdp-post
        COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_OBJECTS:aspf-xdp> "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/aspf.bpf.o"
)
add_dependencies(aspf-xdp-post aspf-xdp)
