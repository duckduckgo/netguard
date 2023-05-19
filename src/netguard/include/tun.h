#ifndef NETGUARD_TUN_H
#define NETGUARD_TUN_H

/**
 * Waits  for the tunnel device to become ready for reading by periodically checking the file descriptor using
 * `select`.
 * It also sends a random UDP packet in each iteration to ensure traffic is being routed through the tunnel.
 * If the tunnel becomes ready, it returns success, else failure
 *
 * @param tun_fd tunnel file descriptor
 * @param is_ipv6_enabled whether IPv6 is enabled or not
 * @return `0` if tunnel becomes ready, -1 otherwise
 */
int wait_for_tunnel_up(int tun_fd, int is_ipv6_enabled);

#endif //NETGUARD_TUN_H
