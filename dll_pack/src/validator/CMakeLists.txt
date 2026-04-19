add_library(validator SHARED
    dllmain.c
    validator.c
)

target_include_directories(validator PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Link against user32 for MessageBox
target_link_libraries(validator PRIVATE user32)
