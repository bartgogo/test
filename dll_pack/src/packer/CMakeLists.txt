add_executable(packer
    main.c
    pe_parser.c
    overlay.c
)

target_include_directories(packer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
