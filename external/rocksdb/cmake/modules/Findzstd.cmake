# - Find zstd
# Find the zstd compression library and includes
#
# zstd_INCLUDE_DIRS - where to find zstd.h, etc.
# zstd_LIBRARIES - List of libraries when using zstd.
# zstd_FOUND - True if zstd found.

find_path(zstd_INCLUDE_DIRS
  NAMES zstd.h
  HINTS ${CMAKE_SOURCE_DIR}/external/zstd)

find_library(zstd_LIBRARIES
  NAMES "zstd_static" "libzstd_static" "zstd" "libzstd"
  HINTS ${PROJECT_BINARY_DIR}/external/zstd)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(zstd DEFAULT_MSG zstd_LIBRARIES zstd_INCLUDE_DIRS)

mark_as_advanced(
  zstd_LIBRARIES
  zstd_INCLUDE_DIRS)

if(zstd_FOUND AND NOT (TARGET zstd::zstd))
  add_library (zstd::zstd UNKNOWN IMPORTED)
  set_target_properties(zstd::zstd
    PROPERTIES
      IMPORTED_LOCATION ${zstd_LIBRARIES}
      INTERFACE_INCLUDE_DIRECTORIES ${zstd_INCLUDE_DIRS})
endif()
