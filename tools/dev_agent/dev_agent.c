/* Standalone Linux host build of the Wespe SNMP agent core, for local
 * integration testing against real SNMP clients (net-snmp's snmpget/
 * snmpwalk/snmpset/snmpbulkwalk, pysnmp, etc.) without any ESP32
 * hardware. Links the exact same components/ber, components/mib, and
 * components/snmp_core sources the firmware uses -- only the transport
 * (plain POSIX sockets instead of lwIP) and the MIB object bindings
 * (in-memory state instead of hal/ hardware drivers) are host-specific,
 * mirroring what components/transport/snmp_udp.c and
 * components/mib/mib_wespe.c do on real hardware.
 *
 * Built as part of host_tests/ (see host_tests/CMakeLists.txt's
 * `dev_agent` target) but is not itself a test -- it's a long-running
 * server, run manually. See docs/testing.md for example sessions. */
#include "ber_types.h"
#include "mib_tree.h"
#include "mib_types.h"
#include "snmp_message.h"
#include "snmp_security_community.h"
#include "snmp_security_usm_stub.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define DEV_AGENT_DEFAULT_PORT 1161
#define MAX_PACKET_LEN 1472

static time_t s_boot_time;
static int32_t s_relay_on = 0;
static int32_t s_temperature_decidegrees = 235; /* fixed mock reading, like sensor_mock.c */

static const uint32_t OID_SYS_DESCR[]     = {1, 3, 6, 1, 2, 1, 1, 1, 0};
static const uint32_t OID_SYS_OBJECT_ID[] = {1, 3, 6, 1, 2, 1, 1, 2, 0};
static const uint32_t OID_SYS_UPTIME[]    = {1, 3, 6, 1, 2, 1, 1, 3, 0};
static const uint32_t OID_SYS_NAME[]      = {1, 3, 6, 1, 2, 1, 1, 5, 0};

static const uint32_t OID_WESPE_TEMPERATURE[]    = {1, 3, 6, 1, 4, 1, 99999, 2, 1, 0};
static const uint32_t OID_WESPE_RELAY_STATE[]    = {1, 3, 6, 1, 4, 1, 99999, 2, 2, 0};
static const uint32_t OID_WESPE_UPTIME_SECONDS[] = {1, 3, 6, 1, 4, 1, 99999, 2, 3, 0};

static mib_result_t get_sys_descr(snmp_varbind_t *vb)
{
    static const char s[] = "Wespe dev-agent (host build -- not real ESP32-S3 hardware)";
    vb->value_tag = BER_TAG_OCTET_STRING;
    vb->octets_len = sizeof(s) - 1;
    memcpy(vb->octets, s, vb->octets_len);
    return MIB_OK;
}

static mib_result_t get_sys_object_id(snmp_varbind_t *vb)
{
    static const uint32_t oid[] = {1, 3, 6, 1, 4, 1, 99999, 1, 1};
    vb->value_tag = BER_TAG_OID;
    vb->oid_value_len = sizeof(oid) / sizeof(oid[0]);
    memcpy(vb->oid_value, oid, sizeof(oid));
    return MIB_OK;
}

static mib_result_t get_sys_uptime(snmp_varbind_t *vb)
{
    vb->value_tag = SNMP_TAG_TIMETICKS;
    vb->int_value = (int32_t)((time(NULL) - s_boot_time) * 100);
    return MIB_OK;
}

static mib_result_t get_sys_name(snmp_varbind_t *vb)
{
    static const char s[] = "wespe-dev-agent";
    vb->value_tag = BER_TAG_OCTET_STRING;
    vb->octets_len = sizeof(s) - 1;
    memcpy(vb->octets, s, vb->octets_len);
    return MIB_OK;
}

static mib_result_t get_temperature(snmp_varbind_t *vb)
{
    vb->value_tag = BER_TAG_INTEGER;
    vb->int_value = s_temperature_decidegrees;
    return MIB_OK;
}

static mib_result_t get_relay_state(snmp_varbind_t *vb)
{
    vb->value_tag = BER_TAG_INTEGER;
    vb->int_value = s_relay_on;
    return MIB_OK;
}

static mib_result_t set_relay_state(const snmp_varbind_t *vb)
{
    if (vb->value_tag != BER_TAG_INTEGER) {
        return MIB_WRONG_TYPE;
    }
    if (vb->int_value != 0 && vb->int_value != 1) {
        return MIB_WRONG_VALUE;
    }
    s_relay_on = vb->int_value;
    fprintf(stderr, "[dev_agent] relay -> %s\n", s_relay_on ? "ON" : "OFF");
    return MIB_OK;
}

static mib_result_t get_wespe_uptime(snmp_varbind_t *vb)
{
    vb->value_tag = SNMP_TAG_GAUGE32;
    vb->int_value = (int32_t)(time(NULL) - s_boot_time);
    return MIB_OK;
}

static const mib_object_t s_mib_ii[] = {
    {OID_SYS_DESCR, 9, BER_TAG_OCTET_STRING, MIB_ACCESS_RO, get_sys_descr, NULL},
    {OID_SYS_OBJECT_ID, 9, BER_TAG_OID, MIB_ACCESS_RO, get_sys_object_id, NULL},
    {OID_SYS_UPTIME, 9, SNMP_TAG_TIMETICKS, MIB_ACCESS_RO, get_sys_uptime, NULL},
    {OID_SYS_NAME, 9, BER_TAG_OCTET_STRING, MIB_ACCESS_RO, get_sys_name, NULL},
};

static const mib_object_t s_mib_wespe[] = {
    {OID_WESPE_TEMPERATURE, 10, BER_TAG_INTEGER, MIB_ACCESS_RO, get_temperature, NULL},
    {OID_WESPE_RELAY_STATE, 10, BER_TAG_INTEGER, MIB_ACCESS_RW, get_relay_state, set_relay_state},
    {OID_WESPE_UPTIME_SECONDS, 10, SNMP_TAG_GAUGE32, MIB_ACCESS_RO, get_wespe_uptime, NULL},
};

int main(int argc, char **argv)
{
    int port = DEV_AGENT_DEFAULT_PORT;
    if (argc > 1) {
        port = atoi(argv[1]);
    }

    s_boot_time = time(NULL);

    mib_registry_register_module(s_mib_ii, sizeof(s_mib_ii) / sizeof(s_mib_ii[0]));
    mib_registry_register_module(s_mib_wespe, sizeof(s_mib_wespe) / sizeof(s_mib_wespe[0]));
    snmp_security_community_init("public", "private");
    snmp_security_usm_stub_init();

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        return 1;
    }

    fprintf(stderr, "[dev_agent] listening on 127.0.0.1:%d (RO community 'public', RW community 'private')\n", port);
    fflush(stderr);

    uint8_t in_buf[MAX_PACKET_LEN];
    uint8_t out_buf[MAX_PACKET_LEN];
    for (;;) {
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        ssize_t n = recvfrom(sock, in_buf, sizeof(in_buf), 0, (struct sockaddr *)&from, &from_len);
        if (n <= 0) {
            continue;
        }
        size_t out_len = snmp_message_process(in_buf, (size_t)n, out_buf, sizeof(out_buf));
        if (out_len == 0) {
            continue;
        }
        sendto(sock, out_buf, out_len, 0, (struct sockaddr *)&from, from_len);
    }
}
