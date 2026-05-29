# PasswordFilterDLL - the LSASS-resident shim.
# Thin layer: marshals the LSA UNICODE_STRING arguments into pwfilter_core, applies
# the verdict, logs metadata to the Event Log. No policy logic lives here.
add_library(PasswordFilterDLL SHARED
  dllmain.cpp
  exports.def
)

target_link_libraries(PasswordFilterDLL PRIVATE pwfilter_core)

# Export the three LSA entry points with undecorated names (exports.def guarantees this
# across toolsets/configs). Keep the output name exactly "PasswordFilterDLL.dll".
set_target_properties(PasswordFilterDLL PROPERTIES
  PREFIX ""
  OUTPUT_NAME "PasswordFilterDLL")
