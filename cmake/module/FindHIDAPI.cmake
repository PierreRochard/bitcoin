# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/license/mit/.

include(FindPackageHandleStandardArgs)

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(HIDAPI_PKG QUIET IMPORTED_TARGET hidapi)
endif()

if(HIDAPI_PKG_FOUND)
  add_library(HIDAPI::HIDAPI ALIAS PkgConfig::HIDAPI_PKG)
  set(HIDAPI_FOUND TRUE)
  set(HIDAPI_VERSION ${HIDAPI_PKG_VERSION})
else()
  find_path(HIDAPI_INCLUDE_DIR NAMES hidapi.h PATH_SUFFIXES hidapi)
  find_library(HIDAPI_LIBRARY NAMES hidapi hidapi-libusb hidapi-hidraw hidapi-darwin)
  find_package_handle_standard_args(HIDAPI
    REQUIRED_VARS HIDAPI_LIBRARY HIDAPI_INCLUDE_DIR
  )
  if(HIDAPI_FOUND AND NOT TARGET HIDAPI::HIDAPI)
    add_library(HIDAPI::HIDAPI UNKNOWN IMPORTED)
    set_target_properties(HIDAPI::HIDAPI PROPERTIES
      IMPORTED_LOCATION "${HIDAPI_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${HIDAPI_INCLUDE_DIR}"
    )
  endif()
endif()
