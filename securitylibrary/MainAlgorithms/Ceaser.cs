using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            string a = plainText.ToUpper();
            string cipher = "";
            int l;
            ///Iterate through each character in the plaintext
            for (int i = 0; i < a.Length; i++)
            {
                ///Convert the character to its ASCII integer value.
                l = Convert.ToInt32(a[i]);
                ///Subtract 65 from the integer value (to get a value between 0 and 25).
                l -= 65;
                ///Add the key to the integer value and take the modulo 26
                ///Cipher = (index of P + key) mod 26
                l = ((l + key) % 26);
                ///Add 65 back to to get the ASCII value
                l += 65;
                ///Convert the integer value back to a character
                ///append it to the cipher string.
                cipher += Convert.ToChar(l);

            }
            return cipher;
        }

        public string Decrypt(string cipherText, int key)
        {
            string cipher = cipherText.ToUpper();
            string plain = "";
            int l;
            ///Iterate through each character in the CipherText
            for (int i = 0; i < cipher.Length; i++)
            {
                l = Convert.ToInt32(cipher[i]);
                l -= 65;
                if (l - key < 0)
                {
                    //If l - key is less than 0, it means that the result of the subtraction is negative.
                    // we need to add 26 to the result to get a positive value that is within the range of 0 to 25.
                    l = (((l - key) + 26) % 26) ;
                    ///Add 65 back to to get the ASCII value
                    l += 65;
                }
                else
                {
                    l = ((l - key) % 26);
                    ///Add 65 back to to get the ASCII value
                    l += 65;
                }
                ///Convert the integer value back to a character
                ///append it to the plain string.
                plain += Convert.ToChar(l);
            }
            return plain;
        }

        public int Analyse(string plainText, string cipherText)
        {
            string plain = plainText.ToLower();
            string cipher = cipherText.ToLower();
            //key= difference between the ASCII value of the first character of the ciphertext
            //and of the ASCII value of the first character the plain text
            int key = cipher[0] - plain[0];
            // If the key is negative, add 26 to it else return key
            if (key < 0)
            {
                key += 26;
            }
            return key;
        }
    }
}