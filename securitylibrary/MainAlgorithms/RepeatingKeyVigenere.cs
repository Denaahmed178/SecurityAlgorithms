using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            char[,] matrix = new char[26, 26];
            int a;
            int k;
            StringBuilder f = new StringBuilder(cipherText.ToUpper());
            StringBuilder n = new StringBuilder(plainText.ToUpper());
            string l = "";
            char x = 'A';
            char y = ' ';
            // to fill the matrix with 26 letters from a to z and in each row shifts a letter
            for (int i = 0; i < 26; i++)
            {
                y = x;
                for (int j = 0; j < 26; j++)
                {
                    matrix[i, j] = y;
                    a = Convert.ToInt32(y);
                    a++;
                    y = Convert.ToChar(a);
                    if (y > 'Z') { y = 'A'; }
                }
                a = Convert.ToInt32(x);
                a++;
                x = Convert.ToChar(a);
            }
            //try every combination to match the cipher letters to obtain the key 
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    int column = Convert.ToInt32(n[i]) - 65;
                    if (matrix[j, column] == f[i])

                    {

                        k = j;
                        k += 65;
                        l += Convert.ToChar(k);

                    }
                }

            }
            // extract the addtional letter , remove it and return the key
            string pattern = "";
            for (int length = 1; length <= l.Length / 2; length++)
            {
                pattern = l.Substring(0, length);
                bool flag = true;

                for (int i = 0; i < l.Length; i++)
                {
                    if (!l[i].Equals(pattern[i % pattern.Length]))
                    {
                        flag = false;
                    }
                }
                if (flag == true)
                {
                    return pattern;
                }
            }
            return pattern;
        }

        public string Decrypt(string cipherText, string key)
        {
            char[,] matrix = new char[26, 26];
            StringBuilder f = new StringBuilder(cipherText.ToUpper());
            StringBuilder pkey = new StringBuilder(key.ToUpper());


            char x = 'A';
            char y = ' ';
            int a;
            int k;
            string l = "";
            // to fill the matrix with 26 letters from a to z and in each row shifts a letter
            for (int i = 0; i < 26; i++)
            {
                y = x;
                for (int j = 0; j < 26; j++)
                {
                    matrix[i, j] = y;
                    a = Convert.ToInt32(y);
                    a++;
                    y = Convert.ToChar(a);
                    if (y > 'Z') { y = 'A'; }
                }
                a = Convert.ToInt32(x);
                a++;
                x = Convert.ToChar(a);
            }
            /*get corresponds to the letter in the plaintext by picking a letter in key and get the row and
           find the ciphertext letter's position in that row, and then select the column label of the corresponding ciphertext */
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    int row = Convert.ToInt32(pkey[i]) - 65;
                    if (matrix[row, j] == f[i])
                    {

                        k = j;
                        k += 65;
                        l += Convert.ToChar(k);
                       
                    }
                }

                if (f.Length > pkey.Length)
                {
                    pkey.Append(pkey[i]);

                }

            }

            return l;
        }

        public string Encrypt(string plainText, string key)
        {
            char[,] matrix = new char[26, 26];
            StringBuilder f = new StringBuilder(plainText.ToUpper());
            StringBuilder pkey = new StringBuilder(key.ToUpper());

            char x = 'A';
            char y = ' ';
            int a;
            // to fill the matrix with 26 letters from a to z and in each row shifts a letter
            for (int i = 0; i < 26; i++)
            {
                y = x;
                for (int j = 0; j < 26; j++)
                {
                    matrix[i, j] = y;
                    a = Convert.ToInt32(y);
                    a++;
                    y = Convert.ToChar(a);
                    if (y > 'Z') { y = 'A'; }
                }
                a = Convert.ToInt32(x);
                a++;
                x = Convert.ToChar(a);
            }
           /*  fill the pkey by repeating the key letters to make it the 
            same length as the plaintext*/
            for (int i = 0; i < f.Length - key.Length; i++)
            {
                if (f.Length > key.Length)
                {
                    pkey.Append(pkey[i]);

                }

            }
            /* convert the letters to integers to get the intersection letter
             and fill the cipher matrix*/
            StringBuilder l = new StringBuilder();
            for (int i = 0; i < pkey.Length; i++)
            {
                int row = Convert.ToInt32(pkey[i]) - 65;
                int column = Convert.ToInt32(f[i]) - 65;
                l.Append(matrix[row, column]);
            }
            string r = Convert.ToString(l);

            return r;
        }
    }
}