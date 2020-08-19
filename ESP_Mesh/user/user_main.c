#include "c_types.h"
#include "mem.h"
#include "ets_sys.h"
#include "osapi.h"
#include "gpio.h"
#include "os_type.h"
#include "lwip/ip.h"
#include "lwip/netif.h"
#include "lwip/dns.h"
#include "lwip/lwip_napt.h"
#include "lwip/ip_route.h"
#include "lwip/app/dhcpserver.h"
#include "lwip/app/espconn.h"
#include "lwip/app/espconn_tcp.h"

#if OTAUPDATE
#include "rboot-api.h"
#include "rboot-ota.h"
#endif

#if ALLOW_PING
#include "lwip/app/ping.h"
#endif

#include "user_interface.h"
#include "string.h"
#include "driver/uart.h"

#include "ringbuf.h"
#include "user_config.h"
#include "config_flash.h"
#include "sys_time.h"
#include "sntp.h"

#include "easygpio.h"

#if WEB_CONFIG
#include "web.h"
#endif



#define os_sprintf_flash(str, fmt, ...)                                    \
    do                                                                     \
    {                                                                      \
        static const char flash_str[] ICACHE_RODATA_ATTR STORE_ATTR = fmt; \
        int flen = (sizeof(flash_str) + 4) & ~3;                           \
        char *f = (char *)os_malloc(flen);                                 \
        os_memcpy(f, flash_str, flen);                                     \
        ets_vsprintf(str, f, ##__VA_ARGS__);                               \
        os_free(f);                                                        \
    } while (0)

uint32_t Vdd;

/* System Task, for signals refer to user_config.h */
#define user_procTaskPrio 0
#define user_procTaskQueueLen 2
os_event_t user_procTaskQueue[user_procTaskQueueLen];
static void user_procTask(os_event_t *events);

static os_timer_t ptimer;

int32_t ap_watchdog_cnt;
int32_t client_watchdog_cnt;

/* Some stats */
uint64_t Bytes_in, Bytes_out, Bytes_in_last, Bytes_out_last;
uint32_t Packets_in, Packets_out, Packets_in_last, Packets_out_last;
uint64_t t_old;

#if DAILY_LIMIT
uint64_t Bytes_per_day;
uint8_t last_date;
#endif

#if TOKENBUCKET
uint64_t t_old_tb;
uint32_t token_bucket_ds, token_bucket_us;
#endif

/* Hold the system wide configuration */
sysconfig_t config;

static ringbuf_t console_rx_buffer, console_tx_buffer;

static ip_addr_t my_ip;
static ip_addr_t dns_ip;
bool connected;
uint8_t my_channel;
bool do_ip_config;
int new_portmap;

static ip_addr_t resolve_ip;

uint8_t mesh_level;
uint8_t uplink_bssid[6];

static netif_input_fn orig_input_ap, orig_input_sta;
static netif_linkoutput_fn orig_output_ap, orig_output_sta;

#if HAVE_ENC28J60
struct netif *eth_netif;
#endif

uint8_t remote_console_disconnect;
struct espconn *currentconn;

void ICACHE_FLASH_ATTR user_set_softap_wifi_config(void);
void ICACHE_FLASH_ATTR user_set_softap_ip_config(void);
void ICACHE_FLASH_ATTR user_set_station_config(void);

void ICACHE_FLASH_ATTR to_console(char *str)
{
    ringbuf_memcpy_into(console_tx_buffer, str, os_strlen(str));
}

void ICACHE_FLASH_ATTR mac_2_buff(char *buf, uint8_t mac[6])
{
    os_sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}




// call back for dns lookup
static void ICACHE_FLASH_ATTR dns_resolved(const char *name, ip_addr_t *ip, void *arg)
{
    char response[128];

    if (ip == 0)
    {
        os_sprintf(response, "DNS lookup failed for: %s\r\n", name);
    }
    else
    {
        os_sprintf(response, "DNS lookup for %s: " IPSTR "\r\n", name, IP2STR(ip));
    }

    to_console(response);
    system_os_post(0, SIG_CONSOLE_TX, (ETSParam)currentconn);
}

#if ALLOW_PING
struct ping_option ping_opt;
uint8_t ping_success_count;

void ICACHE_FLASH_ATTR user_ping_recv(void *arg, void *pdata)
{
    struct ping_resp *ping_resp = pdata;
    struct ping_option *ping_opt = arg;
    char response[128];

    if (ping_resp->ping_err == -1)
    {
        os_sprintf(response, "ping failed\r\n");
    }
    else
    {
        os_sprintf(response, "ping recv bytes: %d time: %d ms\r\n", ping_resp->bytes, ping_resp->resp_time);
        ping_success_count++;
    }

    to_console(response);
    system_os_post(0, SIG_CONSOLE_TX_RAW, (ETSParam)currentconn);
}

void ICACHE_FLASH_ATTR user_ping_sent(void *arg, void *pdata)
{
    char response[128];

    os_sprintf(response, "ping finished (%d/%d)\r\n", ping_success_count, ping_opt.count);
    to_console(response);
    system_os_post(0, SIG_CONSOLE_TX, (ETSParam)currentconn);
}

void ICACHE_FLASH_ATTR user_do_ping(const char *name, ip_addr_t *ipaddr, void *arg)
{
    if (ipaddr == NULL)
    {
        char response[128+os_strlen(name)];

        os_sprintf(response, "DNS lookup failed for: %s\r\n", name);
        to_console(response);
        system_os_post(0, SIG_CONSOLE_TX, (ETSParam)currentconn);
        return;    
    }

    ping_opt.count = 4;       //  try to ping how many times
    ping_opt.coarse_time = 2; // ping interval
    ping_opt.ip = ipaddr->addr;
    ping_success_count = 0;

    ping_regist_recv(&ping_opt, user_ping_recv);
    ping_regist_sent(&ping_opt, user_ping_sent);

    ping_start(&ping_opt);
}
#endif




static void ICACHE_FLASH_ATTR patch_netif(ip_addr_t netif_ip, netif_input_fn ifn, netif_input_fn *orig_ifn, netif_linkoutput_fn ofn, netif_linkoutput_fn *orig_ofn, bool nat)
{
    struct netif *nif;

    for (nif = netif_list; nif != NULL && nif->ip_addr.addr != netif_ip.addr; nif = nif->next)
        ;
    if (nif == NULL)
        return;

    nif->napt = nat ? 1 : 0;
    if (ifn != NULL && nif->input != ifn)
    {
        *orig_ifn = nif->input;
        nif->input = ifn;
    }
    if (ofn != NULL && nif->linkoutput != ofn)
    {
        *orig_ofn = nif->linkoutput;
        nif->linkoutput = ofn;
    }
}

int ICACHE_FLASH_ATTR parse_str_into_tokens(char *str, char **tokens, int max_tokens)
{
    char *p, *q, *end;
    int token_count = 0;
    bool in_token = false;

    // preprocessing
    for (p = q = str; *p != 0; p++)
    {
        if (*(p) == '%' && *(p + 1) != 0 && *(p + 2) != 0)
        {
            // quoted hex
            uint8_t a;
            p++;
            if (*p <= '9')
                a = *p - '0';
            else
                a = toupper(*p) - 'A' + 10;
            a <<= 4;
            p++;
            if (*p <= '9')
                a += *p - '0';
            else
                a += toupper(*p) - 'A' + 10;
            *q++ = a;
        }
        else if (*p == '\\' && *(p + 1) != 0)
        {
            // next char is quoted - just copy it, skip this one
            *q++ = *++p;
        }
        else if (*p == 8)
        {
            // backspace - delete previous char
            if (q != str)
                q--;
        }
        else if (*p <= ' ')
        {
            // mark this as whitespace
            *q++ = 0;
        }
        else
        {
            *q++ = *p;
        }
    }

    end = q;
    *q = 0;

    // cut into tokens
    for (p = str; p != end; p++)
    {
        if (*p == 0)
        {
            if (in_token)
            {
                in_token = false;
            }
        }
        else
        {
            if (!in_token)
            {
                tokens[token_count++] = p;
                if (token_count == max_tokens)
                    return token_count;
                in_token = true;
            }
        }
    }
    return token_count;
}

char *console_output = NULL;
void console_send_response(struct espconn *pespconn, uint8_t do_cmd)
{
    uint16_t len = ringbuf_bytes_used(console_tx_buffer);
    console_output = (char *)os_malloc(len + 4);

    ringbuf_memcpy_from(console_output, console_tx_buffer, len);
    
    if (do_cmd)
    {
        os_memcpy(&console_output[len], "CMD>", 4);
        len += 4;
    }

    if (pespconn != NULL)
    {
        espconn_send(pespconn, console_output, len);
    }
    else
    {
        UART_Send(0, console_output, len);
        os_free(console_output);
        console_output = NULL;
    }
}

#if ALLOW_SCANNING
void ICACHE_FLASH_ATTR scan_done(void *arg, STATUS status)
{
    char response[128];

    if (status == OK)
    {
        struct bss_info *bss_link = (struct bss_info *)arg;

        ringbuf_memcpy_into(console_tx_buffer, "\r", 1);
        while (bss_link != NULL)
        {
            os_sprintf(response, "%d,\"%s\",%d,\"" MACSTR "\",%d\r\n",
                       bss_link->authmode, bss_link->ssid, bss_link->rssi,
                       MAC2STR(bss_link->bssid), bss_link->channel);
            to_console(response);

typedef struct
{
    uint32_t gpio_status;
    os_timer_t timer;
} status_timer_t;

void ICACHE_FLASH_ATTR int_timerchange_func(void *arg)
{
    status_timer_t *inttimerchange = arg;
    uint32_t gpio_status = inttimerchange->gpio_status;
    uint16_t pin;
    for (pin = 0; pin <= 16; pin++)
    {
        if (gpio_status & BIT(pin))
        {
            handlePinValueChange(pin);

            // Reactivate interrupts for GPIO
            gpio_pin_intr_state_set(GPIO_ID_PIN(pin), GPIO_PIN_INTR_ANYEDGE);
        }
    }

    os_free(inttimerchange);
}

LOCAL void gpio_change_handler(void *arg)
{
    uint16_t pin = (intptr_t)arg; // not used

    uint32 gpio_status = GPIO_REG_READ(GPIO_STATUS_ADDRESS);
    for (pin = 0; pin <= 16; pin++)
    {
        if (gpio_status & BIT(pin))
        {
            gpio_pin_intr_state_set(GPIO_ID_PIN(pin), GPIO_PIN_INTR_DISABLE);
        }
    }

    // Clear interrupt status
    GPIO_REG_WRITE(GPIO_STATUS_W1TC_ADDRESS, gpio_status);

    // Start the timer
    status_timer_t *inttimerchange = os_malloc(sizeof(status_timer_t));
    inttimerchange->gpio_status = gpio_status;
    os_timer_setfn(&inttimerchange->timer, int_timerchange_func, inttimerchange);
    os_timer_arm(&inttimerchange->timer, 0, 0);
}

#endif /* GPIO_CMDS */

#if GPIO_CMDS
static os_timer_t duration_timer[17];

void ICACHE_FLASH_ATTR set_high(void *arg)
{
    uint16_t pin = (intptr_t)arg;
    do_outputSet(pin, 1, 0);
}

void ICACHE_FLASH_ATTR set_low(void *arg)
{
    uint16_t pin = (intptr_t)arg;
    do_outputSet(pin, 0, 0);
}

void do_outputSet(uint8_t pin, uint8_t value, uint16_t duration)
{
    os_timer_disarm(&duration_timer[pin]);
    easygpio_outputSet(pin, value);

    if (duration > 0)
    {
        os_timer_setfn(&duration_timer[pin], value > 0 ? set_low : set_high, (void *)(uint32_t)pin);
        os_timer_arm(&duration_timer[pin], duration * 1000, 0);
    }
}
#endif

// Use this from ROM instead
int ets_str2macaddr(uint8 *mac, char *str_mac);
#define parse_mac ets_str2macaddr

static char INVALID_LOCKED[] = "Invalid command. Config locked\r\n";
static char INVALID_NUMARGS[] = "Invalid number of arguments\r\n";
static char INVALID_ARG[] = "Invalid argument\r\n";



#if ALLOW_PING
    if (strcmp(tokens[0], "ping") == 0)
    {
        if (nTokens != 2)
        {
            os_sprintf(response, INVALID_NUMARGS);
            goto command_handled;
        }
        currentconn = pespconn;
        uint32_t result = espconn_gethostbyname(NULL, tokens[1], &resolve_ip, user_do_ping);
        if (result == ESPCONN_OK)
        {
            user_do_ping(tokens[1], &resolve_ip, NULL);
        }
        else if (result == ESPCONN_INPROGRESS)
        {
            // lookup taking place, will call dns_resolved on completion
            return;
        }
        else
        {
            os_sprintf(response, "DNS lookup failed for: %s\r\n", tokens[1]);
        }
        goto command_handled;
    }
#endif


bool ICACHE_FLASH_ATTR check_connection_access(struct espconn *pesp_conn, uint8_t access_flags)
{
    remot_info *premot = NULL;
    ip_addr_t *remote_addr;
    bool is_local;

    remote_addr = (ip_addr_t *)&(pesp_conn->proto.tcp->remote_ip);
    //os_printf("Remote addr is %d.%d.%d.%d\r\n", IP2STR(remote_addr));
    is_local = (remote_addr->addr & 0x00ffffff) == (config.network_addr.addr & 0x00ffffff);

    if (is_local && (access_flags & LOCAL_ACCESS))
        return true;
    if (!is_local && (access_flags & REMOTE_ACCESS))
        return true;

    return false;
}



#if WEB_CONFIG
static void ICACHE_FLASH_ATTR handle_set_cmd(void *arg, char *cmd, char *val)
{
    struct espconn *pespconn = (struct espconn *)arg;
    int max_current_cmd_size = MAX_CON_CMD_SIZE - (os_strlen(cmd) + 1);
    char cmd_line[MAX_CON_CMD_SIZE + 1];

    if (os_strlen(val) >= max_current_cmd_size)
    {
        val[max_current_cmd_size] = '\0';
    }
    os_sprintf(cmd_line, "%s %s", cmd, val);
    //os_printf("web_config_client_recv_cb(): cmd line:%s\n",cmd_line);

    ringbuf_memcpy_into(console_rx_buffer, cmd_line, os_strlen(cmd_line));
    console_handle_command(pespconn);
}

char *strstr(char *string, char *needle);
char *strtok(char *str, const char *delimiters);
char *strtok_r(char *s, const char *delim, char **last);

static void ICACHE_FLASH_ATTR web_config_client_recv_cb(void *arg,
                                                        char *data,
                                                        unsigned short length)
{
    struct espconn *pespconn = (struct espconn *)arg;
    char *kv, *sv;
    bool do_reset = false;
    char *token[1];
    char *str;

    str = strstr(data, " /?");
    if (str != NULL)
    {
        str = strtok(str + 3, " ");

        char *keyval = strtok_r(str, "&", &kv);
        while (keyval != NULL)
        {
            char *key = strtok_r(keyval, "=", &sv);
            char *val = strtok_r(NULL, "=", &sv);

            keyval = strtok_r(NULL, "&", &kv);
            //os_printf("web_config_client_recv_cb(): key:%s:val:%s:\n",key,val);
            if (val != NULL)
            {

                if (strcmp(key, "ssid") == 0)
                {
                    parse_str_into_tokens(val, token, 1);
                    handle_set_cmd(pespconn, "set ssid", token[0]);
                    config.automesh_mode = AUTOMESH_OFF;
                    do_reset = true;
                }
                else if (strcmp(key, "password") == 0)
                {
                    parse_str_into_tokens(val, token, 1);
                    handle_set_cmd(pespconn, "set password", token[0]);
                    do_reset = true;
                }
                else if (strcmp(key, "am") == 0)
                {
                    config.automesh_mode = AUTOMESH_LEARNING;
                    config.automesh_checked = 0;
                    do_reset = true;
                }
                else if (strcmp(key, "lock") == 0)
                {
                    os_memcpy(config.lock_password, config.password, sizeof(config.lock_password));
                    config.locked = 1;
                }
                else if (strcmp(key, "ap_ssid") == 0)
                {
                    parse_str_into_tokens(val, token, 1);
                    handle_set_cmd(pespconn, "set ap_ssid", token[0]);
                    do_reset = true;
                }
                else if (strcmp(key, "ap_password") == 0)
                {
                    parse_str_into_tokens(val, token, 1);
                    handle_set_cmd(pespconn, "set ap_password", token[0]);
                    do_reset = true;
                }
                else if (strcmp(key, "network") == 0)
                {
                    handle_set_cmd(pespconn, "set network", val);
                    do_reset = true;
                }
                else if (strcmp(key, "unlock_password") == 0)
                {
                    handle_set_cmd(pespconn, "unlock", val);
                }
                else if (strcmp(key, "ap_open") == 0)
                {
                    if (strcmp(val, "wpa2") == 0)
                    {
                        config.ap_open = 0;
                        do_reset = true;
                    }
                    if (strcmp(val, "open") == 0)
                    {
                        config.ap_open = 1;
                        do_reset = true;
                    }
                }
                else if (strcmp(key, "reset") == 0)
                {
                    do_reset = true;
                }
#if GPIO_CMDS
                else if (strcmp(key, "gpio") == 0)
                {
                    handle_set_cmd(pespconn, "gpio", val);
                }
#endif
            }
        }

        config_save(&config);

        if (do_reset == true)
        {
            do_reset = false;
            ringbuf_memcpy_into(console_rx_buffer, "reset", os_strlen("reset"));
            console_handle_command(pespconn);
        }
    }
}

static void ICACHE_FLASH_ATTR web_config_client_discon_cb(void *arg)
{
    //os_printf("web_config_client_discon_cb(): client disconnected\n");
    struct espconn *pespconn = (struct espconn *)arg;
}

static void ICACHE_FLASH_ATTR web_config_client_sent_cb(void *arg)
{
    //os_printf("web_config_client_sent_cb(): data sent to client\n");
    struct espconn *pespconn = (struct espconn *)arg;

    espconn_disconnect(pespconn);
}

/* Called when a client connects to the web config */
static void ICACHE_FLASH_ATTR web_config_client_connected_cb(void *arg)
{

    struct espconn *pespconn = (struct espconn *)arg;

    //os_printf("web_config_client_connected_cb(): Client connected\r\n");

    if (!check_connection_access(pespconn, config.config_access))
    {
        os_printf("Client disconnected - no config access on this network\r\n");
        espconn_disconnect(pespconn);
        return;
    }

    espconn_regist_disconcb(pespconn, web_config_client_discon_cb);
    espconn_regist_recvcb(pespconn, web_config_client_recv_cb);
    espconn_regist_sentcb(pespconn, web_config_client_sent_cb);

    ringbuf_reset(console_rx_buffer);
    ringbuf_reset(console_tx_buffer);

    if (!config.locked)
    {
        static const uint8_t config_page_str[] ICACHE_RODATA_ATTR STORE_ATTR = CONFIG_PAGE;
        uint32_t slen = (sizeof(config_page_str) + 4) & ~3;
        uint8_t *config_page = (char *)os_malloc(slen);
        if (config_page == NULL)
            return;
        os_memcpy(config_page, config_page_str, slen);

        uint8_t *page_buf = (char *)os_malloc(slen + 200);
        if (page_buf == NULL)
            return;
        os_sprintf(page_buf, config_page, config.ssid, config.password,
                   config.automesh_mode != AUTOMESH_OFF ? "checked" : "",
                   config.ap_ssid, config.ap_password,
                   config.ap_open ? " selected" : "", config.ap_open ? "" : " selected",
                   IP2STR(&config.network_addr));
        os_free(config_page);

        espconn_send(pespconn, page_buf, os_strlen(page_buf));

        os_free(page_buf);
    }
    else
    {
        static const uint8_t lock_page_str[] ICACHE_RODATA_ATTR STORE_ATTR = LOCK_PAGE;
        uint32_t slen = (sizeof(lock_page_str) + 4) & ~3;
        uint8_t *lock_page = (char *)os_malloc(slen);
        if (lock_page == NULL)
            return;
        os_memcpy(lock_page, lock_page_str, slen);

        espconn_send(pespconn, lock_page, sizeof(lock_page_str));

        os_free(lock_page);
    }
}
#endif /* WEB_CONFIG */

bool toggle;
// Timer cb function
void ICACHE_FLASH_ATTR timer_func(void *arg)
{
    uint32_t Vcurr;
    uint64_t t_new;
    uint32_t t_diff;
#if TOKENBUCKET
    uint32_t Bps;
#endif

    toggle = !toggle;

    // Check if watchdogs
    if (toggle)
    {
        if (ap_watchdog_cnt >= 0)
        {
            if (ap_watchdog_cnt == 0)
            {
                os_printf("AP watchdog reset\r\n");
                system_restart();
                while (true)
                    ;
            }
            ap_watchdog_cnt--;
        }

        if (client_watchdog_cnt >= 0)
        {
            if (client_watchdog_cnt == 0)
            {
                os_printf("Client watchdog reset\r\n");
                system_restart();
                while (true)
                    ;
            }
            client_watchdog_cnt--;
        }
    }

    // Check the HW factory reset pin
    static count_hw_reset;
    if (config.hw_reset <= 16)
    {
        bool pin_in = easygpio_inputGet(config.hw_reset);
        if (!pin_in)
        {
            count_hw_reset++;
            if (toggle)
                os_printf(".");
            if (count_hw_reset > 6)
            {
                if (config.status_led <= 16)
                    easygpio_outputSet(config.status_led, true);
                os_printf("\r\nFactory reset\r\n");
                uint16_t pin = config.hw_reset;
                config_load_default(&config);
                config.hw_reset = pin;
                config_save(&config);
                blob_zero(0, sizeof(struct portmap_table) * config.max_portmap);
                system_restart();
                while (true)
                    ;
            }
        }
        else
        {
            count_hw_reset = 0;
        }
    }

    if (config.status_led <= 16)
        easygpio_outputSet(config.status_led, toggle && connected);

    // Power measurement
    // Measure Vdd every second, sliding mean over the last 16 secs
    if (toggle)
    {

        Vcurr = (system_get_vdd33() * 1000) / 1024;
        Vdd = (Vdd * 3 + Vcurr) / 4;

    }

    // Do we still have to configure the AP netif?
    if (do_ip_config)
    {
        user_set_softap_ip_config();
        do_ip_config = false;
    }

#if DAILY_LIMIT
    if (connected && toggle)
    {
        uint32_t current_stamp = sntp_get_current_timestamp();
        if (current_stamp != 0)
        {
            char *s = sntp_get_real_time(current_stamp);
            if (last_date != atoi(&s[8]))
            {
                Bytes_per_day = 0;
                last_date = atoi(&s[8]);
            }
        }
    }
#endif

    t_new = get_long_systime();

#if TOKENBUCKET
    t_diff = (uint32_t)((t_new - t_old_tb) / 1000);
    if (config.kbps_ds != 0)
    {
        Bps = config.kbps_ds * 1024 / 8;
        token_bucket_ds += (t_diff * Bps) / 1000;
        if (token_bucket_ds > MAX_TOKEN_RATIO * Bps)
            token_bucket_ds = MAX_TOKEN_RATIO * Bps;
    }
    if (config.kbps_us != 0)
    {
        Bps = config.kbps_us * 1024 / 8;
        token_bucket_us += (t_diff * Bps) / 1000;
        if (token_bucket_us > MAX_TOKEN_RATIO * Bps)
            token_bucket_us = MAX_TOKEN_RATIO * Bps;
    }
    t_old_tb = t_new;
#endif


    os_timer_arm(&ptimer, toggle ? 900 : 100, 0);
}

//Priority 0 Task
static void ICACHE_FLASH_ATTR user_procTask(os_event_t *events)
{
    //os_printf("Sig: %d\r\n", events->sig);

    switch (events->sig)
    {
    case SIG_START_SERVER:
        // Anything else to do here, when the repeater has received its IP?
        break;

    case SIG_CONSOLE_TX:
    case SIG_CONSOLE_TX_RAW:
    {
        struct espconn *pespconn = (struct espconn *)events->par;
        console_send_response(pespconn, events->sig == SIG_CONSOLE_TX);

        if (pespconn != 0 && remote_console_disconnect)
            espconn_disconnect(pespconn);
        remote_console_disconnect = 0;
    }
    break;

    case SIG_CONSOLE_RX:
    {
        struct espconn *pespconn = (struct espconn *)events->par;
        console_handle_command(pespconn);
    }
    break;
#if HAVE_LOOPBACK
    case SIG_LOOPBACK:
    {
        struct netif *netif = (struct netif *)events->par;
        netif_poll(netif);
    }
    break;
#endif

}

/* Callback called when the connection state of the module with an Access Point changes */
void wifi_handle_event_cb(System_Event_t *evt)
{
    uint16_t i;
    uint8_t mac_str[20];

    //os_printf("wifi_handle_event_cb: ");
    switch (evt->event)
    {
    case EVENT_STAMODE_CONNECTED:
        mac_2_buff(mac_str, evt->event_info.connected.bssid);
        os_printf("connect to ssid %s, bssid %s, channel %d\r\n", evt->event_info.connected.ssid, mac_str, evt->event_info.connected.channel);
        my_channel = evt->event_info.connected.channel;
        os_memcpy(uplink_bssid, evt->event_info.connected.bssid, sizeof(uplink_bssid));

        bool wrong_bssid = false;
        if (*(int *)config.bssid != 0)
        {
            for (i = 0; i < 6; i++)
            {
                if (evt->event_info.connected.bssid[i] != config.bssid[i])
                {
                    wrong_bssid = true;
                    os_printf("connect to non configured bssid!");
                    break;
                }
            }
        }

        if (config.automesh_mode == AUTOMESH_OPERATIONAL && wrong_bssid)
        {
            config.automesh_mode = AUTOMESH_LEARNING;
            config_save(&config);
            system_restart();
            while (true)
                ;
            return;
        }

        break;

    case EVENT_STAMODE_DISCONNECTED:
        os_printf("disconnect from ssid %s, reason %d\r\n", evt->event_info.disconnected.ssid, evt->event_info.disconnected.reason);
        connected = false;



        os_memset(uplink_bssid, 0, sizeof(uplink_bssid));
        if (config.automesh_mode == AUTOMESH_OPERATIONAL)
        {
            if (evt->event_info.disconnected.reason == 201)
            {
                wifi_set_opmode(STATION_MODE);
            }

            config.automesh_tries++;

            if (config.automesh_checked)
            {
                if (config.automesh_tries <= 3)
                    break;
                os_printf("Connect to known SSID %s failed, rouge AP?\r\n", config.ssid);
                *(int *)config.bssid = 0;
                config.automesh_mode = AUTOMESH_LEARNING;
            }
            else
            {
                if (config.automesh_tries > 3)
                {
                    os_printf("Initial connect to SSID %s failed, check password - factory reset\r\n", config.ssid);
                    config_load_default(&config);
                }
                else
                {
                    os_printf("Cannot connect to SSID %s - %d. trial\r\n", config.ssid, config.automesh_tries);
                }
            }

            config_save(&config);
            system_restart();
            while (true)
                ;
            return;
        }

        break;

    case EVENT_STAMODE_AUTHMODE_CHANGE:
        //os_printf("mode: %d -> %d\r\n", evt->event_info.auth_change.old_mode, evt->event_info.auth_change.new_mode);
        break;

    case EVENT_STAMODE_GOT_IP:

        if (config.dns_addr.addr == 0)
        {
            dns_ip = dns_getserver(0);
        }
        dhcps_set_DNS(&dns_ip);

        os_printf("ip:" IPSTR ",mask:" IPSTR ",gw:" IPSTR ",dns:" IPSTR "\n", IP2STR(&evt->event_info.got_ip.ip), IP2STR(&evt->event_info.got_ip.mask), IP2STR(&evt->event_info.got_ip.gw), IP2STR(&dns_ip));

        my_ip = evt->event_info.got_ip.ip;
        connected = true;

        patch_netif(my_ip, my_input_sta, &orig_input_sta, my_output_sta, &orig_output_sta, false);

        // Update any predefined portmaps to the new IP addr
        for (i = 0; i < config.max_portmap; i++)
        {
            if (ip_portmap_table[i].valid)
            {
                ip_portmap_table[i].maddr = my_ip.addr;
            }
        }

        if (config.automesh_mode == AUTOMESH_OPERATIONAL)
        {
            wifi_set_opmode(STATIONAP_MODE);
            if (config.automesh_checked == 0)
            {
                config.automesh_checked = 1;
                config_save(&config);
            }
            os_printf("Automesh successfully configured and started\r\n");
        }



        // Post a Server Start message as the IP has been acquired to Task with priority 0
        system_os_post(user_procTaskPrio, SIG_START_SERVER, 0);
        break;

    case EVENT_SOFTAPMODE_STACONNECTED:
        os_sprintf(mac_str, MACSTR, MAC2STR(evt->event_info.sta_connected.mac));
        os_printf("station: %s join, AID = %d\r\n", mac_str, evt->event_info.sta_connected.aid);

        ip_addr_t ap_ip = config.network_addr;
        ip4_addr4(&ap_ip) = 1;
        patch_netif(ap_ip, my_input_ap, &orig_input_ap, my_output_ap, &orig_output_ap, config.nat_enable);
        break;

    case EVENT_SOFTAPMODE_STADISCONNECTED:
        os_sprintf(mac_str, MACSTR, MAC2STR(evt->event_info.sta_disconnected.mac));
        os_printf("station: %s leave, AID = %d\r\n", mac_str, evt->event_info.sta_disconnected.aid);
        break;

    default:
        break;
    }
}

void ICACHE_FLASH_ATTR user_set_softap_wifi_config(void)
{
    struct softap_config apConfig;

    wifi_softap_get_config(&apConfig); // Get config first.

    os_memset(apConfig.ssid, 0, 32);
    os_sprintf(apConfig.ssid, "%s", config.ap_ssid);
    os_memset(apConfig.password, 0, 64);
    os_sprintf(apConfig.password, "%s", config.ap_password);
    if (!config.ap_open)
        apConfig.authmode = AUTH_WPA_WPA2_PSK;
    else
        apConfig.authmode = AUTH_OPEN;
    apConfig.ssid_len = 0; // or its actual length

    apConfig.max_connection = config.max_clients; // how many stations can connect to ESP8266 softAP at most.
    apConfig.ssid_hidden = config.ssid_hidden;

    // Set ESP8266 softap config
    wifi_softap_set_config(&apConfig);
}

void ICACHE_FLASH_ATTR user_set_softap_ip_config(void)
{
    struct ip_info info;
    struct dhcps_lease dhcp_lease;
    struct netif *nif;
    int i;

    // Configure the internal network

    // Find the netif of the AP (that with num != 0)
    for (nif = netif_list; nif != NULL && nif->num == 0; nif = nif->next)
        ;
    if (nif == NULL)
        return;
    // If is not 1, set it to 1.
    // Kind of a hack, but the Espressif-internals expect it like this (hardcoded 1).
    nif->num = 1;

    wifi_softap_dhcps_stop();

    info.ip = config.network_addr;
    ip4_addr4(&info.ip) = 1;
    info.gw = info.ip;
    IP4_ADDR(&info.netmask, 255, 255, 255, 0);

    wifi_set_ip_info(nif->num, &info);

    dhcp_lease.start_ip = config.network_addr;
    ip4_addr4(&dhcp_lease.start_ip) = 2;
    dhcp_lease.end_ip = config.network_addr;
    ip4_addr4(&dhcp_lease.end_ip) = 128;
    wifi_softap_set_dhcps_lease(&dhcp_lease);

    wifi_softap_dhcps_start();

    // Change the DNS server again
    dhcps_set_DNS(&dns_ip);

    // Enter any saved dhcp enties if they are in this network
    for (i = 0; i < config.dhcps_entries; i++)
    {
        if ((config.network_addr.addr & info.netmask.addr) == (config.dhcps_p[i].ip.addr & info.netmask.addr))
            dhcps_set_mapping(&config.dhcps_p[i].ip, &config.dhcps_p[i].mac[0], 100000 /* several month */);
    }
}

#if WPA2_PEAP
void ICACHE_FLASH_ATTR user_set_wpa2_config()
{
    wifi_station_set_wpa2_enterprise_auth(1);

    //This is an option. If not call this API, the outer identity will be "anonymous@espressif.com".
    wifi_station_set_enterprise_identity(config.PEAP_identity, os_strlen(config.PEAP_identity));

    wifi_station_set_enterprise_username(config.PEAP_username, os_strlen(config.PEAP_username));
    wifi_station_set_enterprise_password(config.PEAP_password, os_strlen(config.PEAP_password));

    //This is an option for EAP_PEAP and EAP_TTLS.
    //wifi_station_set_enterprise_ca_cert(ca, os_strlen(ca)+1);
}
#endif

void ICACHE_FLASH_ATTR user_set_station_config(void)
{
    struct station_config stationConf;
    //char hostname[40];

    /* Setup AP credentials */
    os_sprintf(stationConf.ssid, "%s", config.ssid);
    os_sprintf(stationConf.password, "%s", config.password);
    if (*(int *)config.bssid != 0)
    {
        stationConf.bssid_set = 1;
        os_memcpy(stationConf.bssid, config.bssid, 6);
    }
    else
    {
        stationConf.bssid_set = 0;
    }
    wifi_station_set_config(&stationConf);

    wifi_station_set_hostname(config.sta_hostname);

    wifi_set_event_handler_cb(wifi_handle_event_cb);

    wifi_station_set_auto_connect(config.auto_connect != 0);
}



void ICACHE_FLASH_ATTR automesh_scan_done(void *arg, STATUS status)
{
    if (status == OK)
    {
        mesh_level = 0xff;
        int rssi = -1000;

        struct bss_info *bss_link;

        for (bss_link = (struct bss_info *)arg; bss_link != NULL; bss_link = bss_link->next.stqe_next)
        {
            if (os_strcmp(bss_link->ssid, config.ssid) == 0)
            {
                uint8_t this_mesh_level;

                os_printf("Found: %d,\"%s\",%d,\"" MACSTR "\",%d",
                          bss_link->authmode, bss_link->ssid, bss_link->rssi,
                          MAC2STR(bss_link->bssid), bss_link->channel);
                if (bss_link->bssid[0] != 0x24 || bss_link->bssid[1] != 0x24)
                {
                    this_mesh_level = 0;
                }
                else
                {
                    this_mesh_level = bss_link->bssid[2];
                }

                // If it is bad quality, give is a handicap of one level
                if (bss_link->rssi < -config.automesh_threshold)
                    this_mesh_level++;

                os_printf(", mesh level: %d\r\n", this_mesh_level);

                // Lower mesh level or same but better RSSI
                if (this_mesh_level < mesh_level ||
                    (this_mesh_level == mesh_level && bss_link->rssi > rssi))
                {
                    rssi = bss_link->rssi;
                    mesh_level = this_mesh_level;
                    os_memcpy(config.bssid, bss_link->bssid, 6);
                }
            }
        }

        if (mesh_level < 0xff)
        {
            os_printf("Using: " MACSTR "\r\n", MAC2STR(config.bssid));

            config.AP_MAC_address[0] = 0x24;
            config.AP_MAC_address[1] = 0x24;
            config.AP_MAC_address[2] = mesh_level + 1;
            os_get_random(&config.AP_MAC_address[3], 3);

            wifi_set_macaddr(SOFTAP_IF, config.AP_MAC_address);
            user_set_softap_wifi_config();

            IP4_ADDR(&config.network_addr, 10, 24, mesh_level + 1, 1);

            config.automesh_mode = AUTOMESH_OPERATIONAL;
            config.automesh_tries = 0;

            config_save(&config);
            //wifi_set_macaddr(SOFTAP_IF, config.AP_MAC_address);

            system_restart();
            while (true)
                ;
            return;
        }
    }
    else
    {
        os_printf("Scan fail !!!\r\n");
    }

    os_printf("No AP with ssid %s found\r\n", config.ssid);


#endif

    wifi_station_scan(NULL, automesh_scan_done);
}

void ICACHE_FLASH_ATTR to_scan(void)
{
    if (config.automesh_mode == AUTOMESH_LEARNING)
    {
        wifi_station_scan(NULL, automesh_scan_done);
    }
}

#if HAVE_LOOPBACK
void ICACHE_FLASH_ATTR *schedule_netif_poll(struct netif *netif)
{
    system_os_post(0, SIG_LOOPBACK, (ETSParam)netif);
    return NULL;
}
#endif

void ICACHE_FLASH_ATTR user_init()
{
    struct ip_info info;
    struct espconn *pCon;

    connected = false;
    do_ip_config = false;
    my_ip.addr = 0;
    Bytes_in = Bytes_out = Bytes_in_last = Bytes_out_last = 0,
    Packets_in = Packets_out = Packets_in_last = Packets_out_last = 0;
    t_old = 0;
    os_memset(uplink_bssid, 0, sizeof(uplink_bssid));

#if DAILY_LIMIT
    Bytes_per_day = 0;
    last_date = 0;
#endif

#if TOKENBUCKET
    t_old_tb = 0;
    token_bucket_ds = token_bucket_us = 0;
#endif

    console_rx_buffer = ringbuf_new(MAX_CON_CMD_SIZE);
    console_tx_buffer = ringbuf_new(MAX_CON_SEND_SIZE);

    gpio_init();
    init_long_systime();

    UART_init_console(BIT_RATE_115200, 0, console_rx_buffer, console_tx_buffer);

    os_printf("\r\n\r\nWiFi Repeater %s starting\r\n\nrunning rom %d\r", ESP_REPEATER_VERSION, rboot_get_current_rom());

    // Load config
    uint8_t config_state = config_load(&config);
    new_portmap = config.max_portmap;
    ip_napt_init(config.max_nat, config.max_portmap);
    if (config_state == 0)
    {
        // valid config in FLASH, can read portmap table
        blob_load(0, (uint32_t *)ip_portmap_table, sizeof(struct portmap_table) * config.max_portmap);
    }
    else
    {
        // clear portmap table
        blob_zero(0, sizeof(struct portmap_table) * config.max_portmap);
    }

    if (config.tcp_timeout != 0)
        ip_napt_set_tcp_timeout(config.tcp_timeout);
    if (config.udp_timeout != 0)
        ip_napt_set_udp_timeout(config.udp_timeout);


    // Config GPIO pin as output
    if (config.status_led == 1)
    {
        // Disable output if serial pin is used as status LED
        system_set_os_print(0);
    }

    ap_watchdog_cnt = config.ap_watchdog;
    client_watchdog_cnt = config.client_watchdog;

    if (config.status_led <= 16)
    {
        easygpio_pinMode(config.status_led, EASYGPIO_NOPULL, EASYGPIO_OUTPUT);
        easygpio_outputSet(config.status_led, 0);
    }
#ifdef FACTORY_RESET_PIN
    if (config.hw_reset <= 16)
    {
        easygpio_pinMode(config.hw_reset, EASYGPIO_PULLUP, EASYGPIO_INPUT);
    }
#endif
#endif
#ifdef USER_GPIO_OUT
    easygpio_pinMode(USER_GPIO_OUT, EASYGPIO_NOPULL, EASYGPIO_OUTPUT);
    easygpio_outputSet(USER_GPIO_OUT, config.gpio_out_status);

#endif

#if GPIO_CMDS
    for (i = 0; i < 17; i++)
    {
        if (config.gpiomode[i] == OUT)
        {
            easygpio_pinMode(i, EASYGPIO_NOPULL, EASYGPIO_OUTPUT);
        }
    }
    for (i = 0; i < 17; i++)
    {
        if (config.gpiomode[i] == IN)
        {


    // In Automesh STA and AP passwords and credentials are the same
    if (config.automesh_mode != AUTOMESH_OFF)
    {
        os_memcpy(config.ap_ssid, config.ssid, sizeof(config.ssid));
        os_memcpy(config.ap_password, config.password, sizeof(config.password));

        if (config.automesh_mode == AUTOMESH_LEARNING)
        {
            config.ap_on = 0;
            config.auto_connect = 0;
        }
        else
        {
            config.ap_on = 1;
            config.auto_connect = 1;
            config.ap_open = os_strncmp(config.password, "none", 4) == 0;
        }
    }

    // Configure the AP and start it, if required
    if (config.dns_addr.addr == 0)
        // Google's DNS as default, as long as we havn't got one from DHCP
        IP4_ADDR(&dns_ip, 8, 8, 8, 8);
    else
        // We have a static DNS server
        dns_ip.addr = config.dns_addr.addr;

    // Now config the STA-Mode
    user_set_station_config();
#if WPA2_PEAP
    if (config.use_PEAP)
    {
        user_set_wpa2_config();
        wifi_station_connect();
    }
#endif

    if (config.ap_on)
    {
        wifi_set_opmode(STATIONAP_MODE);
        wifi_set_macaddr(SOFTAP_IF, config.AP_MAC_address);
        user_set_softap_wifi_config();
        do_ip_config = true;
    }
    else
    {
        wifi_set_opmode(STATION_MODE);
    }
    if (strcmp(config.STA_MAC_address, "random") == 0)
    {
        uint8_t random_mac[6];
        os_get_random(random_mac, 6);
        random_mac[0] &= 0xfe;
        wifi_set_macaddr(STATION_IF, random_mac);
    }
    else
    {
        wifi_set_macaddr(STATION_IF, config.STA_MAC_address);
    }

#if PHY_MODE
    wifi_set_phy_mode(config.phy_mode);
#endif

    if (config.my_addr.addr != 0)
    {
        wifi_station_dhcpc_stop();
        info.ip.addr = config.my_addr.addr;
        info.gw.addr = config.my_gw.addr;
        info.netmask.addr = config.my_netmask.addr;
        wifi_set_ip_info(STATION_IF, &info);
        espconn_dns_setserver(0, &dns_ip);
    }

#if HAVE_LOOPBACK
    loopback_netif_init((netif_status_callback_fn)schedule_netif_poll);
#endif

#if REMOTE_CONFIG
    pCon = (struct espconn *)os_zalloc(sizeof(struct espconn));
    if (config.config_port != 0)
    {
        os_printf("Starting Console TCP Server on port %d\r\n", config.config_port);

        /* Equivalent to bind */
        pCon->type = ESPCONN_TCP;
        pCon->state = ESPCONN_NONE;
        pCon->proto.tcp = (esp_tcp *)os_zalloc(sizeof(esp_tcp));
        pCon->proto.tcp->local_port = config.config_port;

        /* Register callback when clients connect to the server */
        espconn_regist_connectcb(pCon, tcp_client_connected_cb);

        /* Put the connection in accept mode */
        espconn_accept(pCon);
    }
#endif

#if WEB_CONFIG
    pCon = (struct espconn *)os_zalloc(sizeof(struct espconn));
    if (config.web_port != 0)
    {
        os_printf("Starting Web Config Server on port %d\r\n", config.web_port);

        /* Equivalent to bind */
        pCon->type = ESPCONN_TCP;
        pCon->state = ESPCONN_NONE;
        pCon->proto.tcp = (esp_tcp *)os_zalloc(sizeof(esp_tcp));
        pCon->proto.tcp->local_port = config.web_port;

        /* Register callback when clients connect to the server */
        espconn_regist_connectcb(pCon, web_config_client_connected_cb);

        /* Put the connection in accept mode */
        espconn_accept(pCon);
    }
#endif


    // Start the timer
    os_timer_setfn(&ptimer, timer_func, 0);
    os_timer_arm(&ptimer, 500, 0);

    //Start task
    system_os_task(user_procTask, user_procTaskPrio, user_procTaskQueue, user_procTaskQueueLen);
}
