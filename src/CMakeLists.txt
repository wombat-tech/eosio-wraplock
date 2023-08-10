project(wraplock)

set(EOSIO_WASM_OLD_BEHAVIOR "Off")
find_package(cdt)

add_contract( wraplock wraplock wraplock.cpp )
target_include_directories( wraplock PUBLIC ${CMAKE_SOURCE_DIR}/../include )
target_ricardian_directory( wraplock ${CMAKE_SOURCE_DIR}/../ricardian )