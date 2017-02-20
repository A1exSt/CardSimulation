/*
 * Copyright (C) 2013 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example.android.cardemulation;

import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import com.example.android.common.logger.Log;
import java.util.Arrays;

/**
 * This is a sample APDU Service which demonstrates how to interface with the card emulation support
 * added in Android 4.4, KitKat.
 *
 * <p>This sample replies to any requests sent with the string "Hello World". In real-world
 * situations, you would need to modify this code to implement your desired communication
 * protocol.
 *
 * <p>This sample will be invoked for any terminals selecting AIDs of 0xF11111111, 0xF22222222, or
 * 0xF33333333. See src/main/res/xml/aid_list.xml for more details.
 *
 * <p class="note">Note: This is a low-level interface. Unlike the NdefMessage many developers
 * are familiar with for implementing Android Beam in apps, card emulation only provides a
 * byte-array based communication channel. It is left to developers to implement higher level
 * protocol support as needed.
 */
public class CardService extends HostApduService {
    private static final String TAG = "CardService";
    // AID for our loyalty card service.
    private static final String SAMPLE_LOYALTY_CARD_AID = "F222222222";
    // ISO-DEP command HEADER for selecting an AID.
    // Format: [Class | Instruction | Parameter 1 | Parameter 2]
    private static final String SELECT_APDU_HEADER = "00A40400";
    // P1, P2 set to 00 - rest is RFU.
    private static final String GET_PROCESSING_OPTIONS_APDU_HEADER = "80A80000";
    private static final String READ_RECORD_APDU_HEADER = "00B2";
    // "OK" status word sent in response to SELECT AID command (0x9000)
    private static final byte[] SELECT_OK_SW = HexStringToByteArray("9000");
    // "UNKNOWN" status word sent in response to invalid APDU command (0x0000)
    private static final byte[] UNKNOWN_CMD_SW = HexStringToByteArray("0000");
    private static final byte[] SELECT_APDU = BuildSelectApdu(SAMPLE_LOYALTY_CARD_AID);

    /**
     * Called if the connection to the NFC card is lost, in order to let the application know the
     * cause for the disconnection (either a lost link, or another AID being selected by the
     * reader).
     *
     * @param reason Either DEACTIVATION_LINK_LOSS or DEACTIVATION_DESELECTED
     */
    @Override
    public void onDeactivated(int reason) { }

    /**
     * This method will be called when a command APDU has been received from a remote device. A
     * response APDU can be provided directly by returning a byte-array in this method. In general
     * response APDUs must be sent as quickly as possible, given the fact that the user is likely
     * holding his device over an NFC reader when this method is called.
     *
     * <p class="note">If there are multiple services that have registered for the same AIDs in
     * their meta-data entry, you will only get called if the user has explicitly selected your
     * service, either as a default or just for the next tap.
     *
     * <p class="note">This method is running on the main thread of your application. If you
     * cannot return a response APDU immediately, return null and use the {@link
     * #sendResponseApdu(byte[])} method later.
     *
     * @param commandApdu The APDU that received from the remote device
     * @param extras A bundle containing extra data. May be null.
     * @return a byte-array containing the response APDU, or null if no response APDU can be sent
     * at this point.
     */
    // BEGIN_INCLUDE(processCommandApdu)
    @Override
    public byte[] processCommandApdu(byte[] commandApdu, Bundle extras) {
        // TODO: Dont make this so hackish!
        Log.i(TAG, "Received APDU: " + ByteArrayToHexString(commandApdu));
        // If the APDU matches the SELECT AID command for this service,
        // send the loyalty card account number, followed by a SELECT_OK status trailer (0x9000).
        String apduString = HexUtils.bytesToHex(commandApdu);
        byte[] selectResponse = UNKNOWN_CMD_SW;
        if (apduString.startsWith(SELECT_APDU_HEADER)) {//Arrays.equals(SELECT_APDU, commandApdu)) {
            //String account = AccountStorage.GetAccount(this);
            //byte[] accountBytes = account.getBytes();
            if(apduString.contains("325041592E5359532E4444463031")) { //
                selectResponse= HexUtils.hexStringToByteArray("6F2D840E325041592E5359532E4444463031A51BBF0C1861164F07A0000000031010500B56495341204352454449549000");
                Log.i(TAG, "Sending SELECT response: " + ByteArrayToHexString(selectResponse));
            } else if(apduString.contains("A0000000031010")) { //VISA Debit/Credit (Classic)
                selectResponse = HexUtils.hexStringToByteArray("6F 48 84 07 A0 00 00 00 03 10 10 A5 3D 50 0B 56 49 53 41 20 43 52 45 44 49 54 9F 38 18 9F 66 04 9F 02 06 9F 03 06 9F 1A 02 95 05 5F 2A 02 9A 03 9C 01 9F 37 04 9F 12 0F 43 52 45 44 49 54 4F 20 44 45 20 56 49 53 41 87 01 01 90 00".replace(" ", ""));
                Log.i(TAG, "Sending SELECT response: " + ByteArrayToHexString(selectResponse));
            } else {
                Log.i(TAG, "Unknown SELECT APDU: " + apduString);
            }
        } else if (apduString.startsWith(GET_PROCESSING_OPTIONS_APDU_HEADER)) {
            selectResponse = HexUtils.hexStringToByteArray("77 81 E2 82 02 20 00 94 08 18 01 01 01 10 01 02 00 57 11 47 61 73 90 01 01 00 10 D2 21 22 01 19 18 94 44 1F 5F 20 17 41 44 56 54 20 51 56 53 44 43 20 54 45 53 54 20 43 41 52 44 20 30 36 9F 10 07 06 01 0A 03 A0 00 00 9F 26 08 13 9C 78 E1 28 49 3C C0 9F 27 01 80 9F 36 02 00 02 9F 4B 81 80 12 15 E9 74 78 0B A5 2F 18 73 B5 D6 07 58 5C 14 F9 41 B5 62 92 DF 74 B7 4A 5B F7 8A CA 03 2B 21 7B 01 DA FF A8 1B 6E 45 70 95 4E FB CD 94 D0 A3 6F F9 0A 0C 50 82 EF A1 3C 92 16 0B E7 28 36 2D C7 EE 46 50 EE 1F 13 A2 87 9A EB 7E CD 28 6B 00 7D 5A 02 1F E7 00 76 23 C5 95 1B C3 44 CC 62 3B 57 71 A4 E4 43 C6 EB 29 36 E8 D0 3E 2F B8 46 16 FF 5B A0 0B DE 52 38 A9 AE C0 B9 CE 9E D6 5E E2 9F 6C 02 90 80 90 00".replace(" ", ""));
            Log.i(TAG, "Sending GET PROCESSING OPTIONS response: " + ByteArrayToHexString(selectResponse));
        } else if (apduString.startsWith(READ_RECORD_APDU_HEADER )) {
            if(apduString.contains("011C")) { //SFI 3, record 1
                selectResponse = HexUtils.hexStringToByteArray("70 0E 5A 08 47 61 73 90 01 01 00 10 5F 34 01 06 90 00".replace(" ", ""));
                Log.i(TAG, "Sending READ RECORD response: " + ByteArrayToHexString(selectResponse));
            } else if(apduString.contains("0114")) { //SFI 2, record 1
                selectResponse = HexUtils.hexStringToByteArray("70 81 B3 90 81 B0 3C 96 F7 65 8F BC 29 A2 02 F1 91 46 BD E9 21 66 B0 F6 22 1B BC CB 02 E3 26 71 0B 9E 22 9D 16 FA E9 AD 0C 87 4C 06 85 91 6E 19 F0 E3 26 93 EE 20 1B CE 23 59 50 9A 6D 65 72 F8 EC 3F C3 73 12 6B 34 3F 9C B8 15 3D 61 B7 EA B2 D4 2D E1 9D 56 08 31 85 A0 3D D1 4C 26 8D 40 DF 08 35 C5 5E AB FA 38 ED 28 BC E4 2C D0 01 3D A9 4F 80 05 18 B7 53 C2 46 EF FB A0 8F D2 02 9B AD 5D FC F0 DA F0 7B 7D 80 1C 46 5F FD 25 2C 70 B9 21 53 B3 30 D9 5D CA 2F A1 FA AE 2D 01 68 A4 EA 8B 47 5C D8 05 DC 32 AA 96 4C 17 BF CD 2C D5 D0 30 9A B0 EA 76 1B 90 00".replace(" ", ""));
                Log.i(TAG, "Sending READ RECORD response: " + ByteArrayToHexString(selectResponse));
            } else if(apduString.contains("0214")) { // SFI 2, record 2
                selectResponse = HexUtils.hexStringToByteArray("70 81 F5 9F 32 01 03 92 24 50 DA 20 DD A8 95 3B 69 3F ED 84 36 68 31 BA 1E EA 97 F7 8F 79 2A CF 8C B9 8F DF 01 49 A7 B7 8F DA 1C 49 67 8F 01 92 5F 24 03 22 12 31 9F 46 81 B0 17 C9 3F 37 08 A1 E8 22 57 CA 10 C4 BE A9 8E 74 59 4C 9A 67 73 D7 F9 90 B0 AF 29 12 AC 2B 69 F9 51 BD D1 13 DF 76 00 51 72 3B 93 39 86 C1 AD C9 BA 76 6B 2F 3D 35 35 FB 45 DC 7C 91 56 B7 5F 7D B1 E9 8A 48 4D C8 26 03 15 19 95 26 96 7F 92 38 DB BD 75 48 3E BA 67 3B FA C0 98 55 EA 38 7F D7 E2 28 1B F0 FF 5F 2E FF DF 98 65 89 D4 4F 36 DA 95 9A 2C 19 E4 83 D1 6F F9 87 F2 13 42 E5 A5 E6 F7 74 9B 5D 99 43 03 18 E1 AA 40 38 99 F8 F1 F9 07 DD 59 C1 CB 63 F4 9E CC 64 CA 73 96 B7 E5 24 8E 7B D1 6E 80 CA 0D B9 B6 9F 3B 00 C7 F9 1B E3 9F 47 01 03 9F 69 07 01 6E 7D 88 77 90 80 90 00".replace(" ", ""));
                Log.i(TAG, "Sending READ RECORD response: " + ByteArrayToHexString(selectResponse));
            }
        }
        else {
            Log.i(TAG, "Unknown APDU: " + ByteArrayToHexString(commandApdu));
        }
        return selectResponse;
    }
    // END_INCLUDE(processCommandApdu)

    /**
     * Build APDU for SELECT AID command. This command indicates which service a reader is
     * interested in communicating with. See ISO 7816-4.
     *
     * @param aid Application ID (AID) to select
     * @return APDU for SELECT AID command
     */
    public static byte[] BuildSelectApdu(String aid) {
        // Format: [CLASS | INSTRUCTION | PARAMETER 1 | PARAMETER 2 | LENGTH | DATA]
        return HexStringToByteArray(SELECT_APDU_HEADER + String.format("%02X",
                aid.length() / 2) + aid);
    }

    /**
     * Utility method to convert a byte array to a hexadecimal string.
     *
     * @param bytes Bytes to convert
     * @return String, containing hexadecimal representation.
     */
    public static String ByteArrayToHexString(byte[] bytes) {
        final char[] hexArray = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
        char[] hexChars = new char[bytes.length * 2]; // Each byte has two hex characters (nibbles)
        int v;
        for (int j = 0; j < bytes.length; j++) {
            v = bytes[j] & 0xFF; // Cast bytes[j] to int, treating as unsigned value
            hexChars[j * 2] = hexArray[v >>> 4]; // Select hex character from upper nibble
            hexChars[j * 2 + 1] = hexArray[v & 0x0F]; // Select hex character from lower nibble
        }
        return new String(hexChars);
    }

    /**
     * Utility method to convert a hexadecimal string to a byte string.
     *
     * <p>Behavior with input strings containing non-hexadecimal characters is undefined.
     *
     * @param s String containing hexadecimal characters to convert
     * @return Byte array generated from input
     * @throws java.lang.IllegalArgumentException if input length is incorrect
     */
    public static byte[] HexStringToByteArray(String s) throws IllegalArgumentException {
        int len = s.length();
        if (len % 2 == 1) {
            throw new IllegalArgumentException("Hex string must have even number of characters");
        }
        byte[] data = new byte[len / 2]; // Allocate 1 byte per 2 hex characters
        for (int i = 0; i < len; i += 2) {
            // Convert each character into a integer (base-16), then bit-shift into place
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    /**
     * Utility method to concatenate two byte arrays.
     * @param first First array
     * @param rest Any remaining arrays
     * @return Concatenated copy of input arrays
     */
    public static byte[] ConcatArrays(byte[] first, byte[]... rest) {
        int totalLength = first.length;
        for (byte[] array : rest) {
            totalLength += array.length;
        }
        byte[] result = Arrays.copyOf(first, totalLength);
        int offset = first.length;
        for (byte[] array : rest) {
            System.arraycopy(array, 0, result, offset, array.length);
            offset += array.length;
        }
        return result;
    }
}
