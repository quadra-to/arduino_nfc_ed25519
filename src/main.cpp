#include "main.h"

void sign(struct KeyVector *test);
void derivePKey(struct KeyVector *test);

void setup() {
  //---Start serial----//
  Serial.begin(115200);
  Serial.println("------- Emulate Tag --------");
  
  RNG.begin("TestEd25519");
  // RNG.addNoiseSource();

  //---Derive Public key----//
  derivePKey(&keyVector);
  for (uint8_t i = 0; i < sizeof(keyVector.publicKey); i++) {
    Serial.println(keyVector.publicKey[i], HEX);
    inputString += "0123456789ABCDEF"[keyVector.publicKey[i] / 16];
    inputString += "0123456789ABCDEF"[keyVector.publicKey[i] % 16];
    inputString += ' ';
  }
  Serial.println(inputString);

  //---add public key to message----//
  message = NdefMessage();
  message.addTextRecord(inputString);
  messageSize = message.getEncodedSize();
  if (messageSize > sizeof(ndefBuf)) {
      Serial.println("ndefBuf is too small");
      while (1) { }
  }
  inputString = "";
  
  Serial.print("Ndef encoded message size: ");
  Serial.println(messageSize);

  message.encode(ndefBuf);
  
  //---Init NFC----//
  nfc.setNdefFile(ndefBuf, messageSize);
  nfc.setUid(uid);
  nfc.init();

  Serial.println("Begin emulation.");
}

void loop() {
  //---State Machine----//
  switch(state) {
    //---Wait for phone to send public key----//
    case SEND_PUBLIC:
      if (!nfc.emulate())
        Serial.println("timed out");
      else
        Serial.println("mobile device found!");

      state = READ;
    break;

    case READ:
    //---Read incoming message----//
      if (!nfc.emulate())
        Serial.println("timed out");
      else
        Serial.println("mobile device found!");

      if (nfc.writeOccured()) {
        Serial.println("Write occured !");
        uint8_t *tag_buf;
        uint16_t length;

        nfc.getContent(&tag_buf, &length);
        NdefMessage ndefMsg = NdefMessage(tag_buf, length);
        ndefMsg.print();
      
        //---Put NDEF message into hex key.message----//
        //for(uint16_t i = 0; i < ndefMsg.getRecord(0).getPayloadLength(); i++) {
        if (ndefMsg.getRecord(0).getPayloadLength() <= MESSAGE_MAX_LENGTH) {
          Serial.println("Payload recieved");

          //Minus five to remove ndef data from string length
          keyVector.len = ndefMsg.getRecord(0).getPayloadLength();
          byte hexstring[keyVector.len] = "";
          ndefMsg.getRecord(0).getPayload(hexstring);

          //---Convert from string to hex array----//
          Serial.println("Converting");
          //Null terminated to remove the end data
          hexstring[keyVector.len] = '\0';
          //Plus 3 to remove first characters (ndef data)
          token = strtok((char*)hexstring + 3, seperator);
          uint16_t i = 0;
          while (token != NULL) {
            Serial.println(token);
            keyVector.message[i] = strtoul(token, NULL, 16);
            i++;
            token = strtok(NULL, seperator);
          }
          keyVector.len = i;

          Serial.println("Message:");
          for (uint8_t i = 0; i < keyVector.len; i++) {
            Serial.println(keyVector.message[i]);
          }
        }
        else {
          Serial.println("Payload to long for signing");
        }

        state = SIGN;
      }
      
    break;

    case SIGN:
    //---Sign message----//
      if (keyVector.len > 0) {
        Serial.print("keyVector.len: ");
        Serial.println(keyVector.len);

        Serial.println("keyVector.messsage: ");
        for (uint16_t i = 0; i < keyVector.len; i++) {
          Serial.println(keyVector.message[i], HEX);
        }

        sign(&keyVector);
        for (uint16_t i = 0; i < sizeof(keyVector.signature); i++) {
            Serial.println(keyVector.signature[i], HEX);
        }
        keyVector.len = 0;
      }
      else {
        Serial.println("Conversion failed");
      }
    
      state = WRITE;
    break;

    case WRITE:
    //---Write message back to phone----//
      for (uint8_t i = 0; i < sizeof(keyVector.signature); i++) {
        Serial.println(keyVector.signature[i], HEX);
        inputString += "0123456789ABCDEF"[keyVector.signature[i] / 16];
        inputString += "0123456789ABCDEF"[keyVector.signature[i] % 16];
        inputString += ' ';
      }

      message = NdefMessage();
      message.addTextRecord(inputString);
      messageSize = message.getEncodedSize();
      if (messageSize > sizeof(ndefBuf)) {
        Serial.println("ndefBuf is too small");
        while (1) { }
      }
      message.encode(ndefBuf);
      nfc.setNdefFile(ndefBuf, messageSize);

      if (!nfc.emulate())
        Serial.println("Timed out");
      else
        Serial.println("Signature written");

      inputString = "";
      state = READ;
    break;
  }
}

int x2i(char *s) 
{
  int x = 0;
  for(;;) {
    char c = *s;
    if (c >= '0' && c <= '9') {
      x *= 16;
      x += c - '0'; 
    }
    else if (c >= 'A' && c <= 'F') {
      x *= 16;
      x += (c - 'A') + 10; 
    }
    else if (c >= 'a' && c <= 'f') {
      x *= 16;
      x += (c - 'a') + 10;
    }
    else break;
    s++;
  }
  return x;
}

void sign(struct KeyVector *test) {
  Serial.println("---Sign---");
  Serial.flush();

  Ed25519::sign(test->signature, test->privateKey, test->publicKey,
                test->message, test->len);
}

void derivePKey(struct KeyVector *test) {
  Serial.println("---Derive public key---");
  Serial.flush();

  Ed25519::derivePublicKey(test->publicKey, test->privateKey);
}