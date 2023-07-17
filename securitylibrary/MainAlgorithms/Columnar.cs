using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            //Initialize key & initialize col >>number of key 
            List<int> Key = new List<int>();
            int col = Key.Count;
            //convert PT & CT to upper case
            string plainText1 = plainText.ToUpper();
            string cipherText1 = cipherText.ToUpper();
            int index1 = 0, index2 = 0;

            //1-find first characters matching in PT & CT
            for (int i = 0; i < plainText1.Length; i++)
            {
                if (cipherText1[0] == plainText1[i] && plainText1[i] != plainText1[i + 1])
                {
                    index1 = i;
                    break;
                }
            }
            //if found store it
            for (int i = index1 + 1; i < plainText1.Length; i++)
            {
                if (cipherText1[1] == plainText1[i])
                {
                    index2 = i;
                    break;
                }
            }

            col = index2 - index1;//set col >> difference between 2-character matching

            //calculate number of rows needed in matrix 
            double row = 0;

            if (plainText1.Length % col == 0)
            {
                row = plainText1.Length / col;
            }
            else
            {
                row = (plainText1.Length / col) + 1;

            }
            //make loop if pt_length divide by  row not equal 0 >>if found empty cell add "X"
            while (plainText1.Length % row != 0)
            {
                plainText1 += 'x';
            }
            //Initialize two matrices for PT & CT
            char[,] matrix = new char[(int)row, col];
            char[,] matrix2 = new char[(int)row, col];
            int counter = 0;
            //fill first matrix PT
            for (int r = 0; r < row; r++)
            {
                for (int c = 0; c < col; c++)
                {
                    matrix[r, c] = plainText1[counter];
                    counter++;
                }
            }




            if ((col * row) > cipherText1.Length)
            {
                double diff = (col * row) - (cipherText1.Length);
                double num = cipherText1.Length - (row - 1);
                cipherText1 = cipherText1.Insert(cipherText1.Length, 'X'.ToString());
                for (int i = 0; i < diff - 1; i++)
                {
                    cipherText1 = cipherText1.Insert(Convert.ToInt32(num), 'X'.ToString());
                    num = num - (row - 1);
                }
            }
            //fill second matrix CT
            int co = 0;
            for (int r = 0; r < col; r++)
            {
                for (int c = 0; c < row; c++)
                {
                    matrix2[c, r] = cipherText1[co];
                    co++;

                }

            }
            // Use the two matrices to determine the key
            int k = 0;
            for (int i = 0; i < col; i++)
            {
                for (int j = 0; j < col; j++)
                {

                    if (matrix[k, i] == matrix2[k, j])
                    {
                        if (matrix[k + 1, i] == matrix2[k + 1, j])
                            Key.Add(j + 1);
                    }

                }


            }
            //final step find positions for character PT & CT 
            int a = 0;
            double b = 0;
            for (int i = 0; i < col; i++)
            {
                for (int j = 0; j < cipherText1.Length - 1; j++)
                {
                    if (matrix[0, i] == cipherText1[j])
                        if (matrix[1, i] == cipherText1[j + 1])
                        {
                            a = j;
                            b = (a / row) + 1;


                        }
                }
                //F I N A L L Y >>add key
                Key.Add(Convert.ToInt32(b));
            }

            return Key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {


            //throw new NotImplementedException();
            //initialize variables
            int col = key.Count;
            double row = cipherText.Length / key.Count;
            string PT = "";



            //make conditions to get right row 
            //1-ct divisible by col equal 0 adding 1
            if (cipherText.Length % col != 0)
            {
                row = (cipherText.Length / col) + 1;
            }
            //2-else not equal 0 
            else
            {
                row = (cipherText.Length / col);
            }
            //Sort Key to get right PT 
            SortedDictionary<int, int> NewKey = new SortedDictionary<int, int>();
            for (int k = 0; k < key.Count; k++)
            {
                NewKey.Add(key[k], k);

            }
            // Fill the matrix with the ciphertext 
            char[,] matrix = new char[(int)row, col];
            int count = 0;
            for (int j = 1; j <= col; j++)
            {
                for (int i = 0; i < row; i++)
                {
                    if (!(count == cipherText.Length))
                    {
                        matrix[i, NewKey[j]] += cipherText[count];
                        count++;
                    }
                }

            }

            //Get Plaintext from the matrix 
            
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    PT += matrix[i, j];

                }

            }
            return PT.ToUpper();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            // throw new NotImplementedException();
            //initialize variables
            int col = key.Count;
            double row;
            string CT = "";
            //make conditions to get right row 
            //1-pt divisible by col equal 0 adding 1
            if (plainText.Length % col != 0)
            {
                row = (plainText.Length / col) + 1;
            }
            //2-else not equal 0 
            else
            {
                row = (plainText.Length / col);
            }

            //make loop if pt_length divide by  row not equal 0 >>if found empty cell add "X"
            while (plainText.Length % row != 0)
            {
                plainText += 'x';
            }
            char[,] matrix = new char[(int)row, col];
            int counter = 0;
            //Fill Matrix with the plaintext 
            for (int r = 0; r < row; r++)
            {

                for (int c = 0; c < col; c++)
                {

                    matrix[r, c] = plainText[counter];

                    counter++;

                }

            }
            //Sort key to get right CT
            SortedDictionary<int, int> NewKey = new SortedDictionary<int, int>();
            for (int k = 0; k < key.Count; k++)
            {
                NewKey.Add(key[k], k);

            }
            //Get CigherText
            for (int j = 1; j <= col; j++)
            {

                for (int i = 0; i < row; i++)
                {
                    CT += matrix[i, NewKey[j]];
                }
            }
            CT = CT.ToUpper();
            return CT;
        }
    }
}
