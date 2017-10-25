#include "packet_dissector.h"

int main(int argc, char *argv[]) {
    FILE *pgpBinFile;
    packet_header header;
    publicKey_packet packet;
    uint8_t byte;

    pgpBinFile=fopen(argv[1],"rb");
    if (!pgpBinFile) {
	printf("Unable to open file !\n");
	return 1;
    }

    fread(&byte, sizeof(uint8_t), 1, pgpBinFile);

    if (!(byte & ALWAYS_ONE_BIT)) {
	printf("Bad PGP Packet !\n");	
	return 1;
    }	

    if (byte & NEW_FORMAT_BIT) {
	header.newFormat = 1;
	header.type = (byte & PACKET_TAG_NEW) >> PACKET_TAG_OFFSET_NEW;
	printf("New format packet\n");
    }
    else {
	header.newFormat = 0;
	header.type = (byte & PACKET_TAG_OLD) >> PACKET_TAG_OFFSET_OLD;
	printf("Old format packet\n");
    }

    if (!(header.newFormat)) {
	switch (byte & LENGTH_TYPE) {
	    case 0:
		printf("1 octet length, 2 octets long header\n");
		fread(&(header.length), sizeof(uint8_t), 1, pgpBinFile);
		break;
	    case 1:
		printf("2 octets length, 3 octets long header\n");
		fread(&(header.length), sizeof(uint16_t), 1, pgpBinFile);
		break;
	    case 2:
		printf("4 octets length, 5 octets long header\n");
		fread(&(header.length), sizeof(uint32_t), 1, pgpBinFile);
		break;
	    case 3:
		printf("indeterlinate length, 1 octet long header\n");
		return 1;
		break;
	}
    }
    else {

    }

    printf("Packet length : %d\n", header.length);
    
    switch (header.type) {
	case PUBLIC_KEY_PACKET_TYPE:
	    printf("Public-Key Packet\n");
	    fread(&byte, sizeof(uint8_t), 1, pgpBinFile);
	    switch (byte) {
		case 3:
		    printf("Version 3 Public Key\n");
		    fread(&(packet.creationTime), sizeof(uint32_t), 1, pgpBinFile);
		    printf("Created at %u\n", packet.creationTime);
		    fread(&(packet.validityPeriod), sizeof(uint16_t), 1, pgpBinFile);
		    printf("Expire after %u days\n", packet.validityPeriod);
		    fread(&(packet.algorithm), sizeof(uint8_t), 1, pgpBinFile);
		    switch (packet.algorithm) {
			case PKALG_RSA:
			case PKALG_RSA_ENCRYPT_ONLY:
			case PKALG_RSA_SIGN_ONLY:
			    printf("RSA\n");
			    break;
			case PKALG_ELGAMAL:
			    printf("Elgamal\n");
			    break;
			case PKALG_DSA:
			    printf("DSA\n");
			    break;
		    }
		    break;
		case 4:
		    printf("Version 4 Public Key\n");
		    fread(&(packet.creationTime), sizeof(uint32_t), 1, pgpBinFile);
		    printf("Created at %u\n", packet.creationTime);
		    fread(&(packet.algorithm), sizeof(uint8_t), 1, pgpBinFile);
		    printf("Algorithm : ");
		    switch (packet.algorithm) {
			case PKALG_RSA:
			case PKALG_RSA_ENCRYPT_ONLY:
			case PKALG_RSA_SIGN_ONLY:
			    printf("RSA\n");
			    break;
			case PKALG_ELGAMAL:
			    printf("Elgamal\n");
			    break;
			case PKALG_DSA:
			    printf("DSA\n");
			    break;
		    }
		    break;
	    }
	    break;
	default:
	    printf("Unknown Packet type\n");
	    return 1;
    }

    fclose(pgpBinFile);

    return 0;
}
