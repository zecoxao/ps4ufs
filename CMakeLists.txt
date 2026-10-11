cmake_minimum_required(VERSION 3.19)
project(ps4ufs LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

find_package(Threads REQUIRED)

# PS4 images are hundreds of GB: force 64-bit file offsets everywhere.
add_compile_definitions(_FILE_OFFSET_BITS=64)

# ---------------------------------------------------------------------------
# CLI  (ps4ufs.c unchanged — its own main())
# ---------------------------------------------------------------------------
add_executable(ps4ufs ps4ufs.c)
target_link_libraries(ps4ufs PRIVATE Threads::Threads)
if(WIN32)
  # the core already #ifdef _WIN32's its threads/mkdir; no extra libs needed
endif()

# ---------------------------------------------------------------------------
# Qt GUI  (ps4ufs-qt)
#   qt/core_bridge.c  #includes ps4ufs.c with PS4UFS_GUI -> clean C API
#   qt/*.cpp          Qt Widgets front-end built on that API
# ---------------------------------------------------------------------------
find_package(Qt6 COMPONENTS Widgets Concurrent QUIET)
if(Qt6_FOUND)
  qt_standard_project_setup()

  set(GUI_SOURCES
    qt/main.cpp
    qt/mainwindow.cpp
    qt/mainwindow.h
    qt/core_bridge.c
    qt/core_bridge.h
    qt/worker.h
    qt/viewerdialog.cpp
    qt/viewerdialog.h
  )

  if(WIN32)
    qt_add_executable(ps4ufs-qt WIN32 ${GUI_SOURCES})
  elseif(APPLE)
    qt_add_executable(ps4ufs-qt MACOSX_BUNDLE ${GUI_SOURCES})
    set_target_properties(ps4ufs-qt PROPERTIES
      MACOSX_BUNDLE_BUNDLE_NAME "ps4ufs"
      MACOSX_BUNDLE_GUI_IDENTIFIER "com.zecoxao.ps4ufs"
      MACOSX_BUNDLE_BUNDLE_VERSION "1.0.0"
      MACOSX_BUNDLE_SHORT_VERSION_STRING "1.0.0")
  else()
    qt_add_executable(ps4ufs-qt ${GUI_SOURCES})
  endif()

  # core_bridge.c compiles the C core; keep it C and reachable from C++
  target_include_directories(ps4ufs-qt PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} qt)
  target_link_libraries(ps4ufs-qt PRIVATE Qt6::Widgets Qt6::Concurrent Threads::Threads)
else()
  message(STATUS "Qt6 not found - building CLI only (set CMAKE_PREFIX_PATH to your Qt).")
endif()

install(TARGETS ps4ufs RUNTIME DESTINATION bin)
if(Qt6_FOUND)
  install(TARGETS ps4ufs-qt
    BUNDLE  DESTINATION .
    RUNTIME DESTINATION bin)
endif()
