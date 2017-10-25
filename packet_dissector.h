#include <stdio.h>
#include <inttypes.h>

#define ALWAYS_ONE_BIT 0x80
#define NEW_FORMAT_BIT 0x40
#define PACKET_TAG_OLD 0x3C
#define PACKET_TAG_OFFSET_OLD 2
#define PACKET_TAG_NEW 0x3F 
#define PACKET_TAG_OFFSET_NEW 0
#define LENGTH_TYPE 0x03

#define PUBLIC_KEY_PACKET_TYPE 6

#define PKALG_RSA 1
#define PKALG_RSA_ENCRYPT_ONLY 2
#define PKALG_RSA_SIGN_ONLY 3
#define PKALG_ELGAMAL 16
#define PKALG_DSA 17

struct packet_header {
    uint8_t newFormat;
    uint32_t length;
    uint8_t type;
};
typedef struct packet_header packet_header;

struct publicKey_packet {
    uint8_t version;
    uint32_t creationTime;
    uint16_t validityPeriod;
    uint8_t algorithm;
};
typedef struct publicKey_packet publicKey_packet;
