using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        public static byte[,] SBOX = new byte[16, 16] {
       /* 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f */
      /*0*/ { 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76 },
    /*1*/   { 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0 },
    /*2*/   { 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15 },
    /*3*/   { 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75 },
    /*4*/   { 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84 },
    /*5*/   { 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF },
    /*6*/   { 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8 },
    /*7*/   { 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2 },
     /*8*/  { 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73 },
     /*9*/  { 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB },
     /*a*/  { 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79 },
    /*b*/   { 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08 },
    /*c*/   { 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A },
     /*d*/  { 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E },
    /*e*/   { 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF },
     /*0f*/ { 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 } };

        public static byte[,] Inverse_SBOX = new byte[16, 16] {
       /* 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f */
      /*0*/ {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB },
    /*1*/   { 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB },
    /*2*/   { 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
    /*3*/   { 0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
    /*4*/   {  0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
    /*5*/   { 0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84 },
    /*6*/   {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
    /*7*/   {  0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B },
     /*8*/  {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73 },
     /*9*/  {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E },
     /*a*/  {  0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B },
    /*b*/   { 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
    /*c*/   { 0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F },
     /*d*/  {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF },
    /*e*/   { 0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
     /*0f*/ {  0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D} };

        public override string Decrypt(string cipherText, string key)
        {

            List<string[,]> arr = new List<string[,]> { }; // to store the 10 keys
            string[,] keymatrix = fillmatrix(key);


            // to generate 10 key
            for (int k = 0; k < 10; k++)
            {
                var tmp = new string[0];
                if (k == 0)
                    tmp = shiftcolumns(keymatrix);
                else
                    tmp = shiftcolumns(arr[k - 1]);

                string[,] keyround = new string[4, 4];
                //initial round in the key schedule with input key
                if (keyround[0, 0] == null && k == 0) // Rcon applied to get the first column
                    keyround = Rcon(keymatrix, keyround, tmp, 0);
                if (keyround[0, 0] != null && k == 0)
                    keyround = XOR(keymatrix, keyround);
                //9 rounds using the previous key
                if (keyround[0, 0] == null && k != 0) // Rcon applied to get the first column
                    keyround = Rcon(arr[k - 1], keyround, tmp, k);
                if (keyround[0, 0] != null && k != 0)
                    keyround = XOR(arr[k - 1], keyround);

                arr.Add(keyround);
            }
            // initial round add the 10th key of the  10 keys
            string[,] ctmatrix = fillmatrix(cipherText);
            ctmatrix = addkeyround(arr[9], ctmatrix);
            // 9 main rounds
            for (int i = 8; i >= 0; i--)
            {
                ctmatrix = inverseshiftrows(ctmatrix);
                ctmatrix = inverse_subbyte(ctmatrix);

                ctmatrix = addkeyround(arr[i], ctmatrix);
                ctmatrix = inversemixcolumns(ctmatrix);
            }
            //final round
            ctmatrix = inverseshiftrows(ctmatrix);
            ctmatrix = inverse_subbyte(ctmatrix);
            ctmatrix = addkeyround(keymatrix, ctmatrix);

            //fill the plain
            string plain = "0x";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    plain += ctmatrix[j, i];
                }
            }

            return plain;
        }

        public override string Encrypt(string plainText, string key)
        {

            List<string[,]> arr = new List<string[,]> { }; // to store the 10 keys
            string[,] keymatrix = fillmatrix(key);

            // to generate 10 key
            for (int k = 0; k < 10; k++)
            {
                var tmp = new string[0];
                if (k == 0)
                    tmp = shiftcolumns(keymatrix);
                else
                    tmp = shiftcolumns(arr[k - 1]);

                string[,] keyround = new string[4, 4];
                //initial round in the key schedule with input key
                if (keyround[0, 0] == null && k == 0) // Rcon applied to get the first column
                    keyround = Rcon(keymatrix, keyround, tmp, 0);
                if (keyround[0, 0] != null && k == 0)
                    keyround = XOR(keymatrix, keyround);
                //9 rounds using the previous key
                if (keyround[0, 0] == null && k != 0) // Rcon applied to get the first column
                    keyround = Rcon(arr[k - 1], keyround, tmp, k);
                if (keyround[0, 0] != null && k != 0)
                    keyround = XOR(arr[k - 1], keyround);

                arr.Add(keyround);
            }

            // initial round add the input key
            string[,] ptmatrix = fillmatrix(plainText);
            ptmatrix = addkeyround(keymatrix, ptmatrix);

            // 9 main rounds
            for (int i = 0; i < 9; i++)
            {
                ptmatrix = subbyte(ptmatrix);
                ptmatrix = shiftrows(ptmatrix);

                ptmatrix = mixcolumns(ptmatrix);
                ptmatrix = addkeyround(arr[i], ptmatrix);
            }
            //final round
            ptmatrix = subbyte(ptmatrix);
            ptmatrix = shiftrows(ptmatrix);
            ptmatrix = addkeyround(arr[9], ptmatrix);
            //fill the cipher 
            string cipher = "0x";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    cipher += ptmatrix[j,i];
                }
            }
           return cipher.Replace(" ", "");
        }
        /* to convert each hexastring to string matrix */
        public static string[,] fillmatrix(string input)
        {
            string str = input.Substring(2);
            string[,] matrix = new string[4, 4];
            int h = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    matrix[j, i] = str[h].ToString() + str[h + 1].ToString();
                    h += 2;
                }
            }
            return matrix;
        }
        //key function
        public static string[] shiftcolumns(string[,] keymatrix)
        {
            /* shifts the first element i the first column  of the key 
             stores the result column in an array*/
            string[] tmp = new string[4];

            tmp[0] = (keymatrix[1, 3]);
            tmp[1] = (keymatrix[2, 3]);
            tmp[2] = (keymatrix[3, 3]);
            tmp[3] = (keymatrix[0, 3]);
            /* access the sbox  by converting the the letters from hexa to int of each cell in tmp array 
              to get  the corresponding letter*/
            for (int i = 0; i < 4; i++)
            {
                if (tmp[i].ToString().Length == 1)
                    tmp[i] = tmp[i].ToString().PadLeft(2, '0');
                int row = Convert.ToInt32(tmp[i][0].ToString(), 16);// first letter
                int col = Convert.ToInt32(tmp[i][1].ToString(), 16); //second letter
                tmp[i] = SBOX[row, col].ToString("x");
                if (tmp[i].ToString().Length == 1)
                    tmp[i] = tmp[i].ToString().PadLeft(2, '0');
            }
            return tmp;
        }
        /* key function
          gets the xor between each column in the key matrix with a column from Rcon matrix 
        the column number determined by the number of the round*/
        public static string[,] Rcon(string[,] keymatrix, string[,] keyround, string[] tmp, int c)
        {
            byte[,] rcon = new byte[4, 10]
            {{ 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 },
            { 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            { 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            { 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }};

            for (int i = 0; i < 4; i++)
            {
                var Key1 = Convert.ToInt32(keymatrix[i, 0].ToString(), 16);
                var Key2 = Convert.ToInt32(tmp[i].ToString(), 16);
                var r = rcon[i, c];
                var rr = (Key1 ^ r) ^ Key2;
                keyround[i, 0] = rr.ToString("x"); 
                if (keyround[i, 0].ToString().Length == 1)
                    keyround[i, 0] = keyround[i, 0].ToString().PadLeft(2, '0');

            }
            return keyround;
        }
        /* get the xor between a word in the current state W(i) of key and the pervious word  W(i-4)*/
        public static string[,] XOR(string[,] keymatrix, string[,] keyround)
        {
            for (int j = 1; j < 4; j++)//column
            {
                for (int i = 0; i < 4; i++)//row
                {
                    var Key1 = Convert.ToInt32(keymatrix[i, j].ToString(), 16);
                    var Key2 = Convert.ToInt32(keyround[i, j - 1].ToString(), 16);

                    var rr = Key1 ^ Key2;

                    keyround[i, j] = rr.ToString("x");
                    if (keyround[i, j].ToString().Length == 1)
                        keyround[i, j] = keyround[i, j].ToString().PadLeft(2, '0');

                }
            }
            return keyround;
        }
        
                            /* THE 4 TYPES OF TRANSFORMATION  FOR ENCRYPTION*/

        // to get the xor between the keyround and the current state in the 9 rounds of the plain
        public static string[,] addkeyround(string[,] keymatrix, string[,] plain)
        {
            for (int j = 0; j < 4; j++)//column
            {
                for (int i = 0; i < 4; i++)//row
                {
                    var Key1 = Convert.ToInt32(keymatrix[i, j].ToString(), 16);
                    var Key2 = Convert.ToInt32(plain[i, j].ToString(), 16);

                    var rr = Key1 ^ Key2;

                    plain[i, j] = rr.ToString("x");
                    if (plain[i, j].ToString().Length == 1)
                        plain[i, j] = plain[i, j].ToString().PadLeft(2, '0');

                }
            }
            return plain;
        }
        /* access the sbox  by converting the the letters from hexa to int of each cell in tmp array 
           to get  the corresponding letter*/
        public static string[,] subbyte(string[,] plainmatrix)
        {
            for (int j = 0; j < 4; j++)//col
            {
                for (int i = 0; i < 4; i++)//row
                {
                    if (plainmatrix[i, j].ToString().Length == 1)
                        plainmatrix[i, j] = plainmatrix[i, j].ToString().PadLeft(2, '0');
                    int row = Convert.ToInt32(plainmatrix[i, j][0].ToString(), 16);// first letter
                    int col = Convert.ToInt32(plainmatrix[i, j][1].ToString(), 16); //second letter
                    plainmatrix[i, j] = SBOX[row, col].ToString("x");
                    if (plainmatrix[i, j].ToString().Length == 1)
                        plainmatrix[i, j] = plainmatrix[i, j].ToString().PadLeft(2, '0');
                }
            }
            return plainmatrix;
        }
        // shifts  the elements right of the row by the  row number 
        public static string[,] shiftrows(string[,] state)
        {
            for (int k = 0; k < 4; k++)
            {
                int row = k;
                string[] temp = new string[4];
                for (int i = 0; i < 4; i++)
                    temp[i] = state[row, i];
                for (int i = 0; i < 4; i++)
                    state[row, i] = temp[(i + row) % 4];
            }
            return state;
        }
        //to multiply two numbers using galios field notation
        public static int multiply(byte num, string num2)
        {// var num = 0;
            var num1 = Convert.ToInt32(num2, 16);
            var res = 0;
            if (num == 0x02) // mul by x02
            {
                if (num1 < 0x80)
                    res = (num1 << 1);
                else
                {
                    res = (num1 << 1) ^ 0x1B;
                }
                res %= 0x100;
            }
            if (num == 0x03)//mul by x03
            {
                if (num1 < 0x80) // mul by x02
                    res = (num1 << 1);
                else
                {
                    res = (num1 << 1) ^ 0x1b;
                }
                res %= 0x100;
                res = res ^ num1;

            }
            //mul_by_02(num) ^ num) 
            return res;
        }
        //to multiply the matrix with the using galios field notation
        public static string[,] mixcolumns(string[,] state)
        {
            string[,] result = new string[4, 4];

            var r1 = 0;
            var r2 = 0;
            var r3 = 0;
            var r4 = 0;
            for (int k = 0; k < 4; k++)
            {
               
                r1 = multiply(0x02, state[0, k]) ^ multiply(0x03, state[1, k]) ^ Convert.ToInt32(state[2, k], 16) ^ Convert.ToInt32(state[3, k].ToString(), 16);

                r2 = Convert.ToInt32(state[0, k], 16) ^ multiply(0x02, state[1, k]) ^ multiply(0x03, state[2, k]) ^ Convert.ToInt32(state[3,k].ToString(), 16);

                r3 = Convert.ToInt32(state[0, k], 16) ^ Convert.ToInt32(state[1, k], 16) ^ multiply(0x02, state[2, k]) ^ multiply(0x03, state[3, k]);

                r4 = multiply(0x03, state[0, k]) ^ Convert.ToInt32(state[1, k], 16) ^ Convert.ToInt32(state[2, k], 16) ^ multiply(0x02, state[3, k]);
                result[0,k] = r1.ToString("x");
                if (result[0, k].ToString().Length == 1)
                    result[0, k] = result[0, k].ToString().PadLeft(2, '0');

                result[1, k] = r2.ToString("x");
                if (result[1, k].ToString().Length == 1)
                    result[1, k] = result[1, k].ToString().PadLeft(2, '0');

                result[2, k] = r3.ToString("x");
                if (result[2, k].ToString().Length == 1)
                    result[2, k] = result[2, k].ToString().PadLeft(2, '0');

                result[3, k] = r4.ToString("x");
                if (result[3, k].ToString().Length == 1)
                    result[3, k] = result[3, k].ToString().PadLeft(2, '0');
            }
            return result;
        }

                          /* THE 4 TYPES OF TRANSFORMATION  FOR DECRYPTION*/

        /* access the Inverse_SBOX  by converting the the letters from hexa to int of each cell in tmp array 
              to get  the corresponding letter*/
        public static string[,] inverse_subbyte(string[,] ciphrmatrix)
        {
            for (int j = 0; j < 4; j++)//col
            {
                for (int i = 0; i < 4; i++)//row
                {
                    if (ciphrmatrix[i, j].ToString().Length == 1)
                        ciphrmatrix[i, j] = ciphrmatrix[i, j].ToString().PadLeft(2, '0');
                    int row = Convert.ToInt32(ciphrmatrix[i, j][0].ToString(), 16);// first letter
                    int col = Convert.ToInt32(ciphrmatrix[i, j][1].ToString(), 16); //second letter
                    ciphrmatrix[i, j] = Convert.ToString(Inverse_SBOX[row, col], 16).ToUpper();
                    if (ciphrmatrix[i, j].ToString().Length == 1)
                        ciphrmatrix[i, j] = ciphrmatrix[i, j].ToString().PadLeft(2, '0');
                }
            }
            return ciphrmatrix;
        }
        //inverse shift row of each row
        public static string[,] inverseshiftrows(string[,] state)
        {
            for (int k = 0; k < 4; k++)
            {
                int row = k;
                string[] temp = new string[4];
                for (int i = 0; i < 4; i++)
                    temp[i] = state[row, i];
                for (int i = 0; i < 4; i++)
                    state[row, i] = temp[(i - row + 4) % 4];
            }
            return state;
        }
        //helper functions used to multiply numbers using galios field notation
        public static int multiply(byte num, int num1)
        {
            var res = 0;
            if (num == 0x02) // mul by x02
            {
                if (num1 < 0x80)
                    res = (num1 << 1);
                else
                {
                    res = (num1 << 1) ^ 0x1b;
                }
                res %= 0x100;
            }
            if (num == 0x03)//mul by x03
            {
                if (num1 < 0x80) // mul by x02
                    res = (num1 << 1);
                else
                {
                    res = (num1 << 1) ^ 0x1b;
                }
                res %= 0x100;
                res = res ^ num1;
            }
            return res;
        }
        public static int inversemultiply(byte num, string num2)
        {
            var num1 = Convert.ToInt32(num2.ToString(), 16);
            var res = 0;

            if (num == 0x09)
            {
                res = multiply(0x02, num1);
                res = multiply(0x02, res);
                res = multiply(0x02, res);
                res = res ^ num1;

            }
            if (num == 0x0b)
            {
                res = multiply(0x02, num1);
                res = multiply(0x02, res);
                res = multiply(0x02, res);
                int res2 = multiply(0x02, num1);

              
                res = (res ^ res2) ^ num1;
            }
            if (num == 0x0d)
            {
                res = multiply(0x02, num1);
                res = multiply(0x02, res);
                res = multiply(0x02, res);

                var res2 = multiply(0x02, num1);
                res2 = multiply(0x02, res2);
                res = (res ^ res2) ^ num1;

            }
            if (num == 0x0e)
            {
                res = multiply(0x02, num1);
                res = multiply(0x02, res);
                res = multiply(0x02, res);

                int res2 = multiply(0x02, num1);
                res2 = multiply(0x02, res2);

                int res3 = multiply(0x02, num1);
                res = (res ^ res2) ^ res3;
            }
            return res;
        }
        //to multiply the matrix with the using galios field notation
        public static string[,] inversemixcolumns(string[,] state)
        {
            string[,] result = new string[4, 4];
            var r1 = 0;
            var r2 = 0;
            var r3 = 0;
            var r4 = 0;
            for (int k = 0; k < 4; k++)
            {

                r1 = inversemultiply(0x0E, state[0, k]) ^ inversemultiply(0x0b, state[1, k]) ^ inversemultiply(0x0d, state[2, k]) ^ inversemultiply(0x09, state[3, k]);

                r2 = inversemultiply(0x09, state[0, k]) ^ inversemultiply(0x0e, state[1, k]) ^ inversemultiply(0x0b, state[2, k]) ^ inversemultiply(0x0d, state[3, k]);

                r3 = inversemultiply(0x0d, state[0, k]) ^ inversemultiply(0x09, state[1, k]) ^ inversemultiply(0x0e, state[2, k]) ^ inversemultiply(0x0b, state[3, k]);

                r4 = inversemultiply(0x0b, state[0, k]) ^ inversemultiply(0x0d, state[1, k]) ^ inversemultiply(0x09, state[2, k]) ^ inversemultiply(0x0e, state[3, k]);
                result[0, k] = r1.ToString("x");
                if (result[0, k].ToString().Length == 1)
                    result[0, k] = result[0, k].ToString().PadLeft(2, '0');

                result[1, k] = r2.ToString("x");
                if (result[1, k].ToString().Length == 1)
                    result[1, k] = result[1, k].ToString().PadLeft(2, '0');

                result[2, k] = r3.ToString("x");
                if (result[2, k].ToString().Length == 1)
                    result[2, k] = result[2, k].ToString().PadLeft(2, '0');

                result[3, k] = r4.ToString("x");
                if (result[3, k].ToString().Length == 1)
                    result[3, k] = result[3, k].ToString().PadLeft(2, '0');
            }
            return result;
        }
    }
}