#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define SIZE 80
#define SECONDS 10
struct DataItem {
	char *name;
	int count;
};

struct DataItem* hashArray[SIZE];
struct DataItem* dummyItem;
struct timestamp stop;
struct timestamp start;
time_t start_t;

//CALLBACK FOR PCAP_LOOP
void sniffit(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

//WRITE THE RESULTS TO FILE EVERY SECONDS VARIABLE
void writeToFile() {
	time_t nt = time(NULL);
	struct tm *newt = localtime(&nt);

	//WRITE IN THE SPECIFIC FILE
	FILE *f = fopen("beacon_statistics.txt", "a");
	if (f == NULL) {
		printf("Error opening file!\n");
	}
	else {
		const char *text = "Total beacon packets are";
		char *buffer[SIZE];
		char *beacon;
		int i = 0;
		float count = 0.0;

		//LOOP IN HASH ARRAY 
		for (i = 0; i<SIZE; i++) {
			if (hashArray[i] != NULL) {
				int sizeBeacon = strlen(hashArray[i]->name) + snprintf(0, 0, "%+d", hashArray[i]->count - 1) + 18;
				beacon = malloc(sizeBeacon);
				snprintf(beacon, sizeBeacon, "Name: '%s', Count: %i", hashArray[i]->name, hashArray[i]->count);
				count += hashArray[i]->count;
				buffer[i] = beacon;
			}
			else
				break;
		}

		//WRITE THE CURRENT TIME STAMP
		fprintf(f, "\n##%dh:%dm:%ds: -> %s = %.0f: \n", newt->tm_hour, newt->tm_min, newt->tm_sec, text, count);
		int b = 0;
		for (b = 0; b<i; b++) {
			if (buffer[b] != NULL) {
				//WRITE THE SSID NAME, COUNT AND AVERAGE IN FILE 
				fprintf(f, "       - %s, Average: %.2f%\n", buffer[b], (hashArray[b]->count * 100) / count);
				hashArray[b] = dummyItem; //DELETE THE CURRENT 
			}
			else
				break;
		}
		fclose(f);
	}
}

void insert(char *Name, int size) {
	unsigned int index = 0;

	//FIND FOR THE NEXT POSITION TO STORE IN HASH ARRAY
	while (hashArray[index] != NULL && (0 != strcmp(hashArray[index]->name, Name)))
		index++;

	//IF THERE IS NO SSID IN HASH ARRAY
	if (hashArray[index] == NULL) {
		struct DataItem *item = (struct DataItem*) malloc(sizeof(struct DataItem));
		item->name = malloc(size);
		snprintf(item->name, size, "%s", Name);
		item->count = 1;
		hashArray[index] = item;
	}
	else //IF THERE IS SSID IN HASH ARRAY
		hashArray[index]->count++;

	//CHECK IF THERE IS SPECIFIC DIFFERENCE BETWEEN THE START TIMESTAMP
	double diff_t;
	time_t end_t;
	time(&end_t);
	if (difftime(end_t, start_t) >= SECONDS) {
		printf("Write to file after: %i seconds\n", SECONDS);
		start_t = end_t;
		writeToFile(); //WRITE THE CURRENT STORED SSID NAME, COUNT, AVERAGE
	}

}

//THE CALLBACK METHOD
void sniffit(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

	struct radiotap_header {
		uint8_t it_rev;
		uint8_t it_pad;
		uint16_t it_len;
	};

	const u_char *essid;
	int offset = 0;
	struct radiotap_header *rtaphdr;
	rtaphdr = (struct radiotap_header *) packet;
	offset = rtaphdr->it_len;

	//IN CASE IT IS BEACON PACKET 0x80 TYPE
	if (packet[offset] == 0x80) {
		essid = packet + 56; //ESSID NAME STARTS HERE 

		char *ssid = malloc(packet[55] + 1); //THE LENGTH OF THE ESSID PLUS ONE FINAL
		unsigned int i = 0;
		while (essid[i] > 0x1) {
			ssid[i] = essid[i];
			i++;
		}

		ssid[i] = '\0'; //FINALIZE THE SSID VARIABLE
		//printf("ESSID string: %s\n", ssid);

		insert(ssid, packet[55] + 1); //INSERT THE NAME IN HASH ARRAY
		free(ssid);
	}
	else {
		//printf("ESSID other: %x\n", packet[offset]);
	}
};

//METHOD TO DISPLAY THE HASH ARRAY IN CONSOLE
void display() {
	int i = 0;
	for (i = 0; i<SIZE; i++) {
		if (hashArray[i] != NULL)
			printf(" (%s,%i)\n", hashArray[i]->name, hashArray[i]->count);
		else
			break;
	}
}

//MAIN METHOD
int main(void) {
	char error_buffer[PCAP_ERRBUF_SIZE];
	//struct bpf_program filter;

	//CREATE HANDLE FROM SPECIFIC DEVICE - UNLIMITED READ TIMEOUT
	pcap_t *handle = pcap_open_live("wlan1", BUFSIZ, 1, -1, error_buffer);

	//CREATE FROM CAPTURED FILE
	//pcap_t *handle = pcap_open_offline("capture_file1.pcap", error_buffer);

	time_t t = time(NULL);
	struct tm *tm = localtime(&t);

	if (handle == NULL) {
		printf("Could not open - %s\n", error_buffer);
		return 2;
	}
	else {
		//WRITE TO FILE THAT NEW OPERATION IS STARTED
		FILE *f = fopen("beacon_statistics.txt", "a");
		if (f == NULL) {
			printf("Error opening file!\n");
		}
		else {
			fprintf(f, "################################################### \n");
			fprintf(f, "Started Writing at: %dh %dm %ds \n", tm->tm_hour, tm->tm_min, tm->tm_sec);
			fclose(f);
		}
	}

	//DISPLAY THE TIME STARTED IN CONSOLE
	printf("started at %d:%d:%d\n", tm->tm_hour, tm->tm_min, tm->tm_sec);

	time(&start_t);

	//LOOP IN HANDLE TO GET 5000 PACKETS
	pcap_loop(handle, 5000, sniffit, NULL);

	//CLOSE HANDLE
	pcap_close(handle);

	//METHOD TO DISPLAY HASH ARRAY ITEMS IN CONSOLE
	//display();

	//IT IS NECESSARY TO WRITE IN FILE THE REST OF THE ITEMS 
	writeToFile();


	//WRITE TO FILE WHEN THE OPERATION IS FINISHED
	FILE *f = fopen("beacon_statistics.txt", "a");
	if (f == NULL) {
		printf("Error opening file!\n");
	}
	else {
		time_t nt = time(NULL);
		struct tm *ntm = localtime(&nt);
		printf("finished at %d:%d:%d\n", ntm->tm_hour, ntm->tm_min, ntm->tm_sec);
		fprintf(f, "Finished at: %dh %dm %ds \n\n", ntm->tm_hour, ntm->tm_min, ntm->tm_sec);
		fclose(f);
	}
	return 0;
}