#include <stdio.h>
#include <pcap.h>
void callback_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main(void){
	char error_buffer[PCAP_ERRBUF_SIZE];
	const u_char *packet;
	int timeout;
	int packet_counter = 0;	
	struct pcap_pkthdr header;
	
	printf("Please enter the timeout value: ");
	scanf ("%d", &timeout);

	pcap_t *handler = pcap_create("wlan1", error_buffer);
	if (pcap_set_rfmon(handler, 1) == 0){  /*sets the interface to monitor mode*/
		printf("Monitor mode enabled for wlan1..\n");
	
		pcap_set_snaplen(handler, 2048);
		pcap_set_promisc(handler, 1);  /*set the interface to promiscuous mode - to 			capture others packets */
		pcap_set_timeout(handler, timeout);

		int status = pcap_activate(handler);
		printf("Status activate: %d\n", status);

		if (status == 0){

		packet_counter = pcap_dispatch(handler, 0, callback_packet, NULL);
		printf("Packets captured: %d\n", packet_counter);
		}
		pcap_set_rfmon(handler, 0);
		pcap_close(handler);
	}
	else
	{ printf("Couldn't enable monitor mode for wlan1..\n"); }
	return 0;
}

void callback_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
printf("Packet captured..\n");

};
