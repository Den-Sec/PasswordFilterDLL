# PasswordFilterDLL - the LSASS-resident shim.
# Thin layer: marshals the LSA UNICODE_STRING arguments into pwfilter_core, applies the
# verdict, logs metadata to the Event Log. No policy logic lives here.
add_library(PasswordFilterDLL SHARED
  dllmain.cpp
  config_win.cpp
  eventlog.cpp
  exports.def
  PasswordFilterDLL.rc
)

# advapi32: registry + Event Log APIs. kernel32 (file mapping, env, lstr*) is implicit.
target_link_libraries(PasswordFilterDLL PRIVATE pwfilter_core pwfilter_flags advapi32)

# Event Log message catalog is added in a follow-up step; until then use plain event IDs.
target_compile_definitions(PasswordFilterDLL PRIVATE PWFILTER_HAVE_MC=0)

# Export the three LSA entry points with undecorated names (exports.def guarantees this
# across toolsets/configs). Keep the output name exactly "PasswordFilterDLL.dll".
set_target_properties(PasswordFilterDLL PROPERTIES
  PREFIX ""
  OUTPUT_NAME "PasswordFilterDLL")
