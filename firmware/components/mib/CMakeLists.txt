# MIB registry + object modules. mib_registry.c has no dependency beyond
# ber's type definitions (host-buildable, see host_tests/); mib_ii.c and
# mib_wespe.c additionally bind object getters/setters to hal/.
idf_component_register(
    SRCS "mib_registry.c" "mib_ii.c" "mib_wespe.c"
    INCLUDE_DIRS "include"
    REQUIRES ber hal
)
