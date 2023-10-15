#include <Arduino.h>
#include <SPI.h>
#include <string.h>
#include "secrets.h"
#include "PN532.h"
#include "PN532_SPI.h"
#include "emulatetag.h"
#include "NdefMessage.h"
#include "Crypto.h"
#include "Ed25519.h"
#include "RNG.h"
#include "string.h"

//SPI CS PIN
#define SPI_CS    53

//State machine available states
enum STATE {
    SEND_PUBLIC,
    READ,
    SIGN,
    WRITE
} state;

//Create PN532
PN532_SPI pn532spi(SPI, SPI_CS);
EmulateTag nfc(pn532spi);
//Ndegmessage buffers
uint8_t ndefBuf[240];
NdefMessage message;
uint32_t messageSize;
//Set NFC chipID
uint8_t uid[3] = { 0x12, 0x34, 0x56};
//String formatting
uint16_t count = 0;
String inputString = "";
char seperator[] = " ";
char *token;