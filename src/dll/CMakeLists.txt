# PasswordFilterDLL - the LSASS-resident shim.
# Thin layer: marshals the LSA UNICODE_STRING arguments into pwfilter_core, applies the
# verdict, logs metadata to the Event Log. No policy logic lives here.

set(_gen "${CMAKE_CURRENT_BINARY_DIR}/gen")
file(MAKE_DIRECTORY "${_gen}")

# Locate mc.exe (the Windows SDK "message compiler") to build a proper Event Log message
# catalog. If it cannot be found the DLL still builds and logs - just with plain numeric
# event IDs instead of formatted descriptions (see eventlog.cpp).
set(_pf86 "ProgramFiles(x86)")
file(GLOB _winkit_bin
  "$ENV{${_pf86}}/Windows Kits/10/bin/*/x64"
  "$ENV{ProgramFiles}/Windows Kits/10/bin/*/x64")
get_filename_component(_rcdir "${CMAKE_RC_COMPILER}" DIRECTORY)
find_program(PWFILTER_MC NAMES mc.exe mc HINTS "${_rcdir}" ${_winkit_bin})

set(_have_mc 0)
if(PWFILTER_MC)
  set(_have_mc 1)
  message(STATUS "PasswordFilterDLL: mc.exe = ${PWFILTER_MC} (Event Log catalog enabled)")
  add_custom_command(
    OUTPUT "${_gen}/messages.h" "${_gen}/messages.rc" "${_gen}/MSG00001.bin"
    COMMAND "${PWFILTER_MC}" -U -h "${_gen}" -r "${_gen}" "${CMAKE_CURRENT_SOURCE_DIR}/messages.mc"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/messages.mc"
    COMMENT "Compiling Event Log message catalog (mc.exe)"
    VERBATIM)
  add_custom_target(pwfilter_messages
    DEPENDS "${_gen}/messages.h" "${_gen}/messages.rc" "${_gen}/MSG00001.bin")
  file(WRITE "${_gen}/catalog_table.rc" "#include \"messages.rc\"\n")
else()
  message(WARNING "PasswordFilterDLL: mc.exe not found - Event Log will use plain event IDs.")
  file(WRITE "${_gen}/catalog_table.rc" "// mc.exe not found at configure time; no message catalog.\n")
endif()

add_library(PasswordFilterDLL SHARED
  dllmain.cpp
  config_win.cpp
  eventlog.cpp
  exports.def
  PasswordFilterDLL.rc
)

# advapi32: registry + Event Log APIs. kernel32 (file mapping, env, lstr*) is implicit.
target_link_libraries(PasswordFilterDLL PRIVATE pwfilter_core pwfilter_flags advapi32)
target_include_directories(PasswordFilterDLL PRIVATE "${_gen}")
target_compile_definitions(PasswordFilterDLL PRIVATE PWFILTER_HAVE_MC=${_have_mc})

if(_have_mc)
  add_dependencies(PasswordFilterDLL pwfilter_messages)
  # Ensure the .rc recompiles after, and can resolve, the generated catalog files.
  set_source_files_properties(PasswordFilterDLL.rc PROPERTIES
    OBJECT_DEPENDS "${_gen}/messages.rc;${_gen}/MSG00001.bin;${_gen}/catalog_table.rc"
    INCLUDE_DIRECTORIES "${_gen}")
endif()

# Export the three LSA entry points with undecorated names (exports.def guarantees this
# across toolsets/configs). Keep the output name exactly "PasswordFilterDLL.dll".
set_target_properties(PasswordFilterDLL PROPERTIES
  PREFIX ""
  OUTPUT_NAME "PasswordFilterDLL")
