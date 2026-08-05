cmake_minimum_required(VERSION 3.20)
project(lsb_sentry_smoke C)

if(NOT DEFINED SENTRY_INCLUDE_DIR OR NOT DEFINED SENTRY_LIBRARY_DIR)
  message(FATAL_ERROR "SENTRY_INCLUDE_DIR and SENTRY_LIBRARY_DIR are required")
endif()

add_executable(lsb-sentry-smoke sentry-smoke.c)
target_compile_definitions(lsb-sentry-smoke PRIVATE SENTRY_BUILD_STATIC)
target_compile_options(lsb-sentry-smoke PRIVATE /Zi)
target_link_options(lsb-sentry-smoke PRIVATE /DEBUG)
target_include_directories(lsb-sentry-smoke PRIVATE "${SENTRY_INCLUDE_DIR}")
target_link_directories(lsb-sentry-smoke PRIVATE "${SENTRY_LIBRARY_DIR}")
target_link_libraries(lsb-sentry-smoke PRIVATE
  sentry crashpad_client crashpad_mpack crashpad_util crashpad_compat crashpad_zlib
  mini_chromium dbghelp shlwapi version winhttp user32 advapi32 kernel32
  rpcrt4 powrprof synchronization
)
set_property(TARGET lsb-sentry-smoke PROPERTY
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set_target_properties(lsb-sentry-smoke PROPERTIES
  PDB_NAME "lsb-sentry-smoke"
  COMPILE_PDB_NAME "lsb-sentry-smoke")
