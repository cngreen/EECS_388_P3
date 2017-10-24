import dpkt
import sys
import socket

def main():
	ip_addrs = {}

	pcap_file = sys.argv[1]

	open_pcap = open(pcap_file)

	pcap_reader = dpkt.pcap.Reader(open_pcap)

	for ts, buf in pcap_reader:
		try:
			eth = dpkt.ethernet.Ethernet(buf)
			ip = eth.data
			tcp = ip.data
			port = tcp.sport

			ip_addr_src = socket.inet_ntoa(ip.src)
			# print ip_addr_src

			ip_addr_dst = socket.inet_ntoa(ip.dst)
			# print ip_addr_dst

			if ip_addr_src not in ip_addrs.keys():
				ip_addrs[ip_addr_src] = [0, 0]
			if ip_addr_dst not in ip_addrs.keys():
				ip_addrs[ip_addr_dst] = [0, 0]

			syn_flag = (tcp.flags & dpkt.tcp.TH_SYN) != 0
			ack_flag = (tcp.flags & dpkt.tcp.TH_ACK) != 0

			# print "syn, ", syn_flag
			# print "ack, ", ack_flag

			if syn_flag and ack_flag:
				ip_addrs[ip_addr_dst][0] += 1
			elif syn_flag:
				ip_addrs[ip_addr_src][1] += 1

			# if tcp.dport == 80 and len(tcp.data) > 0:
			# 	http = dpkt.http.Request(tcp.data)
			# 	#print http.uri

		except:
			continue

	open_pcap.close()

	for ip in ip_addrs.keys():
		if ip_addrs[ip][1] > (3 * ip_addrs[ip][0]):
			print ip

	# print ip_addrs

	# print ip_addrs['10.0.2.2']
	# print ip_addrs['10.0.2.3']


if __name__ == "__main__":
	main()