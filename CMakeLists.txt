cmake_minimum_required(VERSION 3.14)
project(KeycardShellModulePlugin LANGUAGES CXX)

if(DEFINED ENV{LOGOS_MODULE_BUILDER_ROOT})
    include($ENV{LOGOS_MODULE_BUILDER_ROOT}/cmake/LogosModule.cmake)
else()
    message(FATAL_ERROR "LOGOS_MODULE_BUILDER_ROOT is not set.")
endif()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/metadata.json
               ${CMAKE_CURRENT_BINARY_DIR}/metadata.json COPYONLY)

logos_module(NAME keycard_shell_module)

# Export only Qt's plugin entry points: the Rust core and libsecp256k1 stay inside the plugin.
if(APPLE)
    target_link_options(keycard_shell_module_module_plugin PRIVATE
        "LINKER:-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/exports/keycard_shell_module.exp")
elseif(UNIX)
    target_link_options(keycard_shell_module_module_plugin PRIVATE
        "LINKER:--version-script=${CMAKE_CURRENT_SOURCE_DIR}/exports/keycard_shell_module.map")
endif()
