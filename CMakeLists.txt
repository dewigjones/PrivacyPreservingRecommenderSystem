cmake_minimum_required(VERSION 3.8.0)
project(PPRS VERSION 0.1.0 LANGUAGES C CXX)

include(vcpkg/scripts/buildsystems/vcpkg.cmake)

include(CTest)
enable_testing()

find_package(SEAL 4.1 REQUIRED)
find_package(cryptopp CONFIG REQUIRED)

add_executable(PPRS src/main.cpp src/RecSys.cpp src/CSP.cpp src/User.cpp src/CSP.hpp)
set(CMAKE_TOOLCHAIN_FILE "/dcs/20/u2009114/Documents/CS310/PrivacPreservingRecommenderSystem/vcpkg/scripts/buildsystems/vcpkg.cmake")
target_link_libraries(PPRS PRIVATE SEAL::seal)
target_link_libraries(PPRS PRIVATE cryptopp::cryptopp)
set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
