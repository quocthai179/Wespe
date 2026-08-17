# MIB registry + object modules. mib_registry.c has no dependency beyond
# ber's type definitions (host-buildable, see host_tests/); mib_ii.c and
# mib_wespe.c additionally bind object getters/setters to device_hal/.
#
# Named "device_hal", not "hal": ESP-IDF ships its own built-in component
# literally named `hal` (chip-level hardware-abstraction headers, e.g.
# hal/sha_types.h, pulled in by mbedtls and others) -- a project component
# also named `hal` silently shadows it and breaks that build in ways that
# have nothing to do with this component's own code. Learned the hard way
# via a failing idf-build.yml CI run; see git history.
idf_component_register(
    SRCS "mib_registry.c" "mib_ii.c" "mib_wespe.c" "mib_iftable.c"
    INCLUDE_DIRS "include"
    REQUIRES ber device_hal
)
