#define MESSAGE_MAX_LENGTH 1024

//Data structure for message signing
struct KeyVector {
  const uint8_t privateKey[32];
  uint8_t publicKey[32];
  uint8_t message[MESSAGE_MAX_LENGTH];
  uint16_t len;
  uint8_t signature[64];
};
//Example privatekey
static KeyVector keyVector = {
  .privateKey = {0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda,
                 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
                 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24,
                 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb}
};