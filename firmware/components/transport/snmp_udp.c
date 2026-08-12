/* UDP transport: the only ESP-IDF/lwIP-specific piece the SNMP agent
 * needs. Everything protocol-related is delegated to
 * snmp_message_process() (components/snmp_core), which knows nothing
 * about sockets -- this file's whole job is "own a socket, hand bytes
 * back and forth". */
#include "snmp_transport.h"
#include "snmp_message.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#define SNMP_AGENT_PORT 161
#define SNMP_TRAP_PORT  162

/* Conservative UDP-safe payload size -- matches the default max message
 * size recommendation from RFC3412 (SNMPv3) that most implementations
 * also apply to v1/v2c, comfortably under Ethernet's ~1500-byte MTU. */
#define SNMP_MAX_PACKET_LEN 1472

static const char *TAG = "snmp_udp";

static int s_trap_socket = -1;
static struct sockaddr_in s_trap_dest;
static int s_trap_dest_valid = 0;

static void snmp_udp_task(void *arg)
{
    (void)arg;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ESP_LOGE(TAG, "socket() failed: errno %d", errno);
        vTaskDelete(NULL);
        return;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(SNMP_AGENT_PORT);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        ESP_LOGE(TAG, "bind(:%d) failed: errno %d", SNMP_AGENT_PORT, errno);
        close(sock);
        vTaskDelete(NULL);
        return;
    }
    ESP_LOGI(TAG, "SNMP agent listening on UDP :%d", SNMP_AGENT_PORT);

    /* Request+response buffers live on this task's stack, so it's created
     * with a generous stack size in snmp_transport_start() -- comfortably
     * more than FreeRTOS's usual default. */
    static uint8_t in_buf[SNMP_MAX_PACKET_LEN];
    static uint8_t out_buf[SNMP_MAX_PACKET_LEN];

    for (;;) {
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        int n = recvfrom(sock, in_buf, sizeof(in_buf), 0, (struct sockaddr *)&from, &from_len);
        if (n < 0) {
            ESP_LOGW(TAG, "recvfrom() failed: errno %d", errno);
            continue;
        }
        if (n == 0) {
            continue;
        }

        size_t out_len = snmp_message_process(in_buf, (size_t)n, out_buf, sizeof(out_buf));
        if (out_len == 0) {
            /* Malformed / unauthorized / nothing to say -- drop silently,
             * per SNMP convention (see snmp_message.h). */
            continue;
        }

        int sent = sendto(sock, out_buf, out_len, 0, (struct sockaddr *)&from, from_len);
        if (sent < 0) {
            ESP_LOGW(TAG, "sendto() failed: errno %d", errno);
        }
    }
}

int snmp_transport_start(void)
{
    BaseType_t ok = xTaskCreate(snmp_udp_task, "snmp_udp", 8192, NULL, tskIDLE_PRIORITY + 5, NULL);
    return (ok == pdPASS) ? 0 : -1;
}

int snmp_transport_set_trap_destination(const char *ipv4_address)
{
    memset(&s_trap_dest, 0, sizeof(s_trap_dest));
    s_trap_dest.sin_family = AF_INET;
    s_trap_dest.sin_port = htons(SNMP_TRAP_PORT);
    if (inet_pton(AF_INET, ipv4_address, &s_trap_dest.sin_addr) != 1) {
        s_trap_dest_valid = 0;
        return -1;
    }
    s_trap_dest_valid = 1;
    return 0;
}

int snmp_transport_send_trap(const uint8_t *packet, size_t len)
{
    if (!s_trap_dest_valid) {
        return -1;
    }
    if (s_trap_socket < 0) {
        s_trap_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s_trap_socket < 0) {
            ESP_LOGW(TAG, "trap socket() failed: errno %d", errno);
            return -1;
        }
    }
    int sent = sendto(s_trap_socket, packet, len, 0, (struct sockaddr *)&s_trap_dest, sizeof(s_trap_dest));
    return (sent == (int)len) ? 0 : -1;
}
