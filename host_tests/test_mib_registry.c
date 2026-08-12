#include "unity_mini.h"
#include "mib_tree.h"

/* Mocked object table -- deliberately independent of mib_ii.c/mib_wespe.c
 * (and therefore of hal/) so this test exercises only the registry's
 * lookup/GETNEXT-walk logic. Two modules are registered to also cover the
 * cross-module lower-bound search. */

static mib_result_t noop_get(snmp_varbind_t *vb)
{
    vb->value_tag = BER_TAG_INTEGER;
    vb->int_value = 42;
    return MIB_OK;
}

/* Module A: 1.3.6.1.2.1.1.{1,3,5}.0 */
static const uint32_t OID_A1[] = {1, 3, 6, 1, 2, 1, 1, 1, 0};
static const uint32_t OID_A3[] = {1, 3, 6, 1, 2, 1, 1, 3, 0};
static const uint32_t OID_A5[] = {1, 3, 6, 1, 2, 1, 1, 5, 0};
static const mib_object_t s_module_a[] = {
    {OID_A1, 9, BER_TAG_INTEGER, MIB_ACCESS_RO, noop_get, NULL},
    {OID_A3, 9, BER_TAG_INTEGER, MIB_ACCESS_RO, noop_get, NULL},
    {OID_A5, 9, BER_TAG_INTEGER, MIB_ACCESS_RO, noop_get, NULL},
};

/* Module B: 1.3.6.1.4.1.99999.2.{1,2}.0 -- interleaves numerically after
 * module A's OIDs but is a separate registered module, exercising the
 * cross-module "pick the smallest candidate" path in find_next. */
static const uint32_t OID_B1[] = {1, 3, 6, 1, 4, 1, 99999, 2, 1, 0};
static const uint32_t OID_B2[] = {1, 3, 6, 1, 4, 1, 99999, 2, 2, 0};
static const mib_object_t s_module_b[] = {
    {OID_B1, 10, BER_TAG_INTEGER, MIB_ACCESS_RO, noop_get, NULL},
    {OID_B2, 10, BER_TAG_INTEGER, MIB_ACCESS_RO, noop_get, NULL},
};

static void setup(void)
{
    mib_registry_reset();
    mib_registry_register_module(s_module_a, 3);
    mib_registry_register_module(s_module_b, 2);
}

UM_TEST(test_oid_compare_basics)
{
    uint32_t a[] = {1, 3, 6};
    uint32_t b[] = {1, 3, 7};
    UM_CHECK(mib_oid_compare(a, 3, b, 3) < 0);
    UM_CHECK(mib_oid_compare(b, 3, a, 3) > 0);
    UM_CHECK_EQ_INT(mib_oid_compare(a, 3, a, 3), 0);

    uint32_t prefix[] = {1, 3};
    UM_CHECK(mib_oid_compare(prefix, 2, a, 3) < 0); /* shorter-is-less on a common prefix */
}

UM_TEST(test_find_exact_match)
{
    setup();
    const mib_object_t *obj = mib_registry_find(OID_A3, 9);
    UM_CHECK(obj != NULL);
    UM_CHECK(obj->oid == OID_A3);
}

UM_TEST(test_find_no_match_returns_null)
{
    setup();
    uint32_t missing[] = {1, 3, 6, 1, 2, 1, 1, 9, 0};
    UM_CHECK(mib_registry_find(missing, 9) == NULL);
}

UM_TEST(test_find_next_walks_within_module)
{
    setup();
    const mib_object_t *obj = mib_registry_find_next(OID_A1, 9);
    UM_CHECK(obj != NULL);
    UM_CHECK(obj->oid == OID_A3);
}

UM_TEST(test_find_next_from_before_first_object)
{
    setup();
    uint32_t before_everything[] = {1};
    const mib_object_t *obj = mib_registry_find_next(before_everything, 1);
    UM_CHECK(obj != NULL);
    UM_CHECK(obj->oid == OID_A1); /* the very first object in the whole MIB view */
}

UM_TEST(test_find_next_crosses_module_boundary)
{
    setup();
    /* One past module A's last object -- the next object lexicographically
     * is module B's first, even though it's a different registered array. */
    const mib_object_t *obj = mib_registry_find_next(OID_A5, 9);
    UM_CHECK(obj != NULL);
    UM_CHECK(obj->oid == OID_B1);
}

UM_TEST(test_find_next_past_end_of_view_returns_null)
{
    setup();
    const mib_object_t *obj = mib_registry_find_next(OID_B2, 10);
    UM_CHECK(obj == NULL);
}

UM_TEST(test_find_next_on_exact_match_returns_strictly_greater)
{
    setup();
    /* GetNext on an OID that itself matches an object must still advance
     * past it (SNMP GETNEXT semantics), not return the same object. */
    const mib_object_t *obj = mib_registry_find_next(OID_A1, 9);
    UM_CHECK(obj != NULL);
    UM_CHECK(obj->oid != OID_A1);
}

UM_TEST(test_registry_count)
{
    setup();
    UM_CHECK_EQ_INT(mib_registry_count(), 5);
}

UM_TEST(test_registry_reset_clears_modules)
{
    setup();
    mib_registry_reset();
    UM_CHECK_EQ_INT(mib_registry_count(), 0);
    UM_CHECK(mib_registry_find(OID_A1, 9) == NULL);
}

int main(void)
{
    UM_RUN(test_oid_compare_basics);
    UM_RUN(test_find_exact_match);
    UM_RUN(test_find_no_match_returns_null);
    UM_RUN(test_find_next_walks_within_module);
    UM_RUN(test_find_next_from_before_first_object);
    UM_RUN(test_find_next_crosses_module_boundary);
    UM_RUN(test_find_next_past_end_of_view_returns_null);
    UM_RUN(test_find_next_on_exact_match_returns_strictly_greater);
    UM_RUN(test_registry_count);
    UM_RUN(test_registry_reset_clears_modules);
    return um_summary();
}
