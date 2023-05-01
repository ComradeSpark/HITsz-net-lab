#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"
#include "udp.h"


/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac)
{
    // TO-DO
    if(buf->len < sizeof(ip_hdr_t))
        return;
    ip_hdr_t* ip_hdr = (ip_hdr_t *)buf->data;

    // ip_hdr check
    if(ip_hdr->version != IP_VERSION_4 || 
        swap16(ip_hdr->total_len16) > buf->len ||
        ip_hdr->hdr_len * IP_HDR_LEN_PER_BYTE != IP_HDR_LEN)
        return;
    
    // checksum check
    uint16_t origin_checksum = ip_hdr->hdr_checksum16;
    ip_hdr->hdr_checksum16 = 0;
    ip_hdr->hdr_checksum16 = checksum16((uint16_t *)buf->data, IP_HDR_LEN);
    if(origin_checksum != ip_hdr->hdr_checksum16)
        return;
    
    // addr check
    if(memcmp(net_if_ip, ip_hdr->dst_ip, NET_IP_LEN) != 0)
        return;
    
    // padding remove
    if(buf->len > swap16(ip_hdr->total_len16))
        buf_remove_padding(buf, buf->len - swap16(ip_hdr->total_len16));

    // sending
    switch (ip_hdr->protocol) {
        // if one of ICMP UDP TCP, send it out
        case NET_PROTOCOL_ICMP:
        case NET_PROTOCOL_UDP:
        // case NET_PROTOCOL_TCP:
            // hdr remove and send
            buf_remove_header(buf, IP_HDR_LEN);
            net_in(buf, ip_hdr->protocol, ip_hdr->src_ip);
            break;
        default:
            icmp_unreachable(buf, ip_hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }

    return;
}

/**
 * @brief 处理一个要发送的ip分片
 * 
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    // TO-DO
    if(offset % 8 != 0)
        return;
    
    // Head Adding and Loading
    buf_add_header(buf, sizeof(ip_hdr_t));

    ip_hdr_t *hdr = (ip_hdr_t *)buf->data;
    hdr->hdr_len = sizeof(ip_hdr_t) / IP_HDR_LEN_PER_BYTE;
    hdr->version = IP_VERSION_4;
    hdr->tos = 0;
    hdr->total_len16 = swap16(buf->len);
    hdr->id16 = swap16(id);

    uint16_t flags_fragment = (offset >> 3) & 0x1fff;
      // Adding MF
    if(mf == 1) flags_fragment |= IP_MORE_FRAGMENT;

    hdr->flags_fragment16 = swap16(flags_fragment);
    hdr->ttl = IP_DEFALUT_TTL;
    hdr->protocol = protocol;

    memcpy(hdr->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(hdr->dst_ip, ip, NET_IP_LEN);

    // Checksum
    hdr->hdr_checksum16 = 0;
    hdr->hdr_checksum16 = checksum16((uint16_t *)buf->data, sizeof(ip_hdr_t));

    // Send
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 * 
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    // TO-DO
    static int send_id = 0;
    size_t max_load_len = 1500 - sizeof(ip_hdr_t);

    // Fragment Send Out
    size_t fragmented_len = 0;
    while(fragmented_len + max_load_len < buf->len) {
        buf_t ip_buf;
        buf_init(&ip_buf, max_load_len);
        memcpy(ip_buf.data, buf->data + fragmented_len, max_load_len);

        // offset per byte
        ip_fragment_out(&ip_buf, ip, protocol, send_id, fragmented_len, 1);
        fragmented_len += max_load_len;
    }
    
    // Tail Processing
    size_t tail_len = buf->len - fragmented_len;
    if(tail_len > 0) {
        buf_t ip_buf_tail;
        buf_init(&ip_buf_tail, tail_len);
        memcpy(ip_buf_tail.data, buf->data + fragmented_len, tail_len);

        ip_fragment_out(&ip_buf_tail, ip, protocol, send_id, fragmented_len, 0);
    }

    // Global Package ID
    send_id++;
}

/**
 * @brief 初始化ip协议
 * 
 */
void ip_init()
{
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}