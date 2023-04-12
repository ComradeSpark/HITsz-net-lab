#include <string.h>
#include <stdio.h>
#include "net.h"
#include "arp.h"
#include "ethernet.h"
/**
 * @brief 初始的arp包
 * 
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = constswap16(ARP_HW_ETHER), //硬件类型
    .pro_type16 = constswap16(NET_PROTOCOL_IP), // 上层协议地址
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP, 
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 * 
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 * 
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 * 
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp)
{
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 * 
 */
void arp_print()
{
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 * 
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip)
{
    // TO-DO
    buf_init(&txbuf, sizeof(arp_pkt_t));

    // 填写ARP数据
    arp_pkt_t *arp_data = (arp_pkt_t *)txbuf.data;
    memcpy(arp_data, &arp_init_pkt, sizeof(arp_pkt_t));
    arp_data->opcode16 = swap16(ARP_REQUEST);
    memcpy(arp_data->target_ip, target_ip, NET_IP_LEN);

    ethernet_out(&txbuf, ether_broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 * 
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac)
{
    // TO-DO
    buf_init(&txbuf, sizeof(arp_pkt_t));

    arp_pkt_t *arp_data = (arp_pkt_t *)txbuf.data;
    memcpy(arp_data, &arp_init_pkt, sizeof(arp_pkt_t));
    arp_data->opcode16 = swap16(ARP_REPLY);
    memcpy(arp_data->target_ip, target_ip, NET_IP_LEN);
    memcpy(arp_data->target_mac, target_mac, NET_MAC_LEN);

    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac)
{
    // TO-DO
    if(buf->len < sizeof(arp_pkt_t))
        return;
    
    arp_pkt_t *arp_data = (arp_pkt_t *)buf->data;
    if(
        arp_data->hw_type16 == swap16(ARP_HW_ETHER) && 
        arp_data->pro_type16 == swap16(NET_PROTOCOL_IP) &&
        arp_data->hw_len == NET_MAC_LEN &&
        arp_data->pro_len == NET_IP_LEN &&
        (arp_data->opcode16 == swap16(ARP_REQUEST) || arp_data->opcode16 == swap16(ARP_REPLY))
    ) {
        map_set(&arp_table, arp_data->sender_ip, arp_data->sender_mac);
        buf_t *cache = map_get(&arp_buf, arp_data->sender_ip);
        if(arp_data->opcode16 == swap16(ARP_REQUEST)) {
            if(memcmp(arp_data->target_ip, net_if_ip, NET_IP_LEN) == 0)
            // 这是在询问本机MAC，回复
                arp_resp(arp_data->sender_ip, arp_data->sender_mac);
        }
        else if(cache != NULL) {
            // 发送上次缓存的数据包，因为MAC已经找到
            ethernet_out(cache, arp_data->sender_mac, NET_PROTOCOL_IP);
            map_delete(&arp_buf, arp_data->sender_ip);
        }
    }
}

/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip)
{
    // TO-DO
    uint8_t *target_mac = map_get(&arp_table, ip);
    if(target_mac != NULL)
        ethernet_out(buf, target_mac, NET_PROTOCOL_IP);
    else { // ARP表中查不到，需要request
        if(map_get(&arp_buf, ip) != NULL) // 正在等待
            return;
        map_set(&arp_buf, ip, buf); // 没有request, ip缓存到arp_buf准备request
        arp_req(ip);
    }
}

/**
 * @brief 初始化arp协议
 * 
 */
void arp_init()
{
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}