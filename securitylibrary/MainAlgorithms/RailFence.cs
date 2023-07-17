using System;
using System.Text;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            //create instance of RailFence class contains encrypt & decrypt methods
            RailFence obj = new RailFence();
            //Initialize value used to store key value if condition true 
            //but still 0 if not matched
            int keyF = 0;
            //make loop trying possible value of key from 1 to 3
            for (int key = 1; key < 4; key++)
            { 
                string plaint = obj.Decrypt(cipherText, key);
                // Compare the resulting decrypted PT with the original PT 
                //if matched >>return current key
                //if not matched >> keyF value  equal 0
                if (plaint == plainText)
                {
                    keyF = key;
                }
            }
            return keyF;
        }

        public string Decrypt(string cipherText, int key)
        {
            //convert CT to string 
            StringBuilder cipherTextF = new StringBuilder(cipherText.ToLower());
            //to calculate number of column >>col=ct_length/key
            double c1 = Convert.ToDouble(cipherTextF.Length) / key;
            double c2 = Math.Ceiling(c1);
            int col = Convert.ToInt32(c2);
            char[,] matrix = new char[key, col];
            //if length of PT no divisible by key append space
            if (cipherTextF.Length % key != 0)
            {
                for (int i = col + (col - 1); i < cipherTextF.Length + (key - 1); i += col)
                {
                    cipherTextF = cipherTextF.Insert(i, ' ');
                }
            }
            //fill matrix with PT >>with col , row (key(depth))
            //fill matrix row by row 
            int k = 0;
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    matrix[i, j] = cipherTextF[k];
                    k++;
                }
            }
            //read PT column by column
            string PT = "";
            for (int i = 0; i < col; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    PT += matrix[j, i];
                }
            }
            //remove any spacing in CT
            StringBuilder p = new StringBuilder(PT);
            for (int j = 0; j < (key - 1); j++)
            {
                for (int i = 0; i < p.Length; i++)
                {
                    if (p[i] == ' ')
                        p.Remove(i, 1);
                }
            }
            //finally convert PT to string and return 
            string plainTF = p.ToString();
            return plainTF;
        }

        public string Encrypt(string plainText, int key)
        {
            //convert PT to lowercase
            StringBuilder plainTextF = new StringBuilder(plainText.ToLower());
            //to calculate number of column >>col=pt_length/key
            double c1 = Convert.ToDouble(plainTextF.Length) / key;
            double c2 = Math.Ceiling(c1);
            int col = Convert.ToInt32(c2);
            char[,] matrix = new char[key, col];
            //if length of PT no divisible by key append space 
            if (plainTextF.Length % key != 0)
            {
                for (int i = 0; i < (key - 1); i++)
                {
                    plainTextF = plainTextF.Append(' ');
                }
            }
            //fill matrix with PT >>with col , row (key(depth))
            //fill matrix column by column 
            int k = 0;
            for (int i = 0; i < col; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    matrix[j, i] = plainTextF[k];
                    k++;
                }
            }
            //read CT row by row
            string CT = "";
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    CT += matrix[i, j];
                }
            }
            //remove any spacing in CT
            StringBuilder c = new StringBuilder(CT);
            for (int j = 0; j < (key - 1); j++)
            {
                for (int i = 0; i < c.Length; i++)
                {
                    if (c[i] == ' ')
                        c.Remove(i, 1);
                }
            }
            //finally convert CT to string and return 
            string ciperTF = c.ToString();
            return ciperTF;
        }
    }
}