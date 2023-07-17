using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            //initialize matrix 5*5 fot CT
            char[,] matrix = new char[5, 5];
            //convert key & CT to lower
            string ct = cipherText.ToLower();
            string keyFinal = key.ToLower();
            string alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ".ToLower();
            //set text1 >>key + alpha to fill matrix CT
            string Text = keyFinal + alphabet;
            //Matrix==============================Text=====================================================
            //replace J with i
            for (int i = 0; i < Text.Length; i++)
            {
                if (Text[i] == 'j')
                    Text.Replace('j', 'i');
            }

            //REMOVE DUPLICATION >> if found same character remove duplicate 

            for (int i = 0; i < key.Length; i++)
            {
                for (int j = i + 1; j < Text.Length; j++)
                {
                    if (key[i] == Text[j])
                        Text = Text.Remove(j, 1);
                }
            }


            //REMOVE SPACE
            for (int i = 0; i < Text.Length; i++)
            {
                if (Text[i] == ' ')
                {
                    Text.Remove(i, 1);
                }
            }
            string TextF = Text.ToString();

            //fill matrix with final key 
            int k = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    matrix[i, j] = TextF[k];
                    k++;
                }
            }
           

            string ct2 = ct.ToString();
            string pText = "";


            int pCharRow1 = 0;
            int pCharCol1 = 0;
            int pCharRow2 = 0;
            int pCharCol2 = 0;

            int r1 = 0;
            int c1 = 0;
            int r2 = 0;
            int c2 = 0;

            //handel cases CT 
            for (int l = 0; l < ct2.Length - 1; l += 2)
            {
                //matrix CT
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        // Find the row and column of the first CT character
                        if (ct2[l] == matrix[i, j])
                        {

                            r1 = i;
                            c1 = j;
                        }
                        // Find the row and column of the second CT character
                        else if (ct2[l + 1] == matrix[i, j])
                        {
                            r2 = i;
                            c2 = j;
                        }
                    }
                }
                //if found 2-character in same row >> choose latter before each latter
                if (r1 == r2)
                {
                    pCharRow1 = r1;
                    pCharRow2 = r2;

                    pCharCol1 = (c1 - 1 + 5) % 5;
                    pCharCol2 = (c2 - 1 + 5) % 5;


                }
                //if found 2-character in same column >> work reverse encrypt
                else if (c1 == c2)
                {
                    pCharCol1 = c1;
                    pCharCol2 = c2;


                    pCharRow1 = (r1 - 1 + 5) % 5;
                    pCharRow2 = (r2 - 1 + 5) % 5;

                }
                //if if found 2-character in different col&row >> take diagonal
                else
                {
                    pCharRow1 = r1;
                    pCharRow2 = r2;

                    pCharCol1 = c2;
                    pCharCol2 = c1;
                }
                pText += matrix[pCharRow1, pCharCol1];
                pText += matrix[pCharRow2, pCharCol2];


            }
            //if  found last character "x" >> remove "x"
            string pnew = pText;
            if (pText[pText.Length - 1] == 'x')
            {
                pnew = pText.Remove(pText.Length - 1);


            }

            //loop PT to handle x
            int x = 0;
            for (int i = 1; i < pnew.Length - 1; i++)
            {
                //1-if found character of PT equal x 
                if (pText[i] == 'x')
                {
                    //2-character before == character after 
                    if (pText[i - 1] == pText[i + 1])
                    {
                        //3-when remove x make shift
                        if (i % 2 != 0 && (i + 1) % 2 == 0 && i + x < pText.Length)
                        {
                            pnew = pnew.Remove(i + x, 1);
                            x--;

                        }
                    }
                }

            }

            return pnew;

        }

        public string Encrypt(string plainText, string key)
        {
            //initialize matrix 5*5 fot PT 
            char[,] matrix = new char[5, 5];
            //convert key & PT to lower
            string keyFinal = key.ToLower();

            StringBuilder plainTextF = new StringBuilder(plainText.ToLower());

            string alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ".ToLower();
            //set text1 >>key + alpha to fill matrix PT
            string Text1 = keyFinal + alphabet;

            StringBuilder Text = new StringBuilder(Text1.ToLower());


            //Matrix==============================Text=====================================================
            //replace all J wih I
            for (int i = 0; i < Text.Length; i++)
            {
                if (Text[i] == 'j')
                    Text.Replace('j', 'i');
            }

            //REMOVE DUPLICATION >> if found same character remove duplicate 
            for (int i = 0; i < key.Length; i++)
                for (int j = i + 1; j < Text.Length; j++)
                {
                    if (key[i] == Text[j])
                        Text.Remove(j, 1);
                }


            //REMOVE SPACE
            for (int i = 0; i < Text.Length; i++)
            {
                if (Text[i] == ' ')
                {
                    Text.Remove(i, 1);
                }
            }
            string TextF = Text.ToString();

            //Fill matrix with text final
            int k = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    matrix[i, j] = TextF[k];
                    k++;
                }
            }

            //PlainText====================================================================================          
            //replace J with i
            for (int i = 0; i < plainTextF.Length; i++)
            {
                if (plainTextF[i] == 'j')
                    plainTextF.Replace('j', 'i');
            }


            //REMOVE SPACE
            for (int i = 0; i < plainTextF.Length; i++)
            {
                if (plainTextF[i] == ' ')
                {
                    plainTextF.Remove(i, 1);
                }
            }

             //handel cases PT 
            for (int l = 0; l < plainTextF.Length - 1; l += 2)
            {

                //1- make condition if found 2-similar character separate wih "x"
                if (plainTextF[l] == plainTextF[l + 1])
                {
                    plainTextF.Insert(l + 1, 'x');


                }
            }
            //2-make condition if length of PT odd append "x"
            if (plainTextF.Length % 2 != 0)
                plainTextF.Append('x');

            string plainTextF2 = plainTextF.ToString();
            string cText = "";


            int cipherCharRow1 = 0;
            int cipherCharCol1 = 0;
            int cipherCharRow2 = 0;
            int cipherCharCol2 = 0;

            int r1 = 0;
            int c1 = 0;
            int r2 = 0;
            int c2 = 0;

            //loop on 2-character in PT
            for (int l = 0; l < plainTextF2.Length; l += 2)
            {
                //matrix PT
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        // Find the row and column of the first plaintext character 
                        if (plainTextF2[l] == matrix[i, j])
                        {

                            r1 = i;
                            c1 = j;
                        }
                        // Find the row and column of the second plaintext character 
                        else if (plainTextF2[l + 1] == matrix[i, j])
                        {
                            r2 = i;
                            c2 = j;
                        }
                    }
                }
                //if found 2-character in same row >> choose latter after each latter
                if (r1 == r2)
                {
                    cipherCharRow1 = r1;
                    cipherCharRow2 = r2;

                    cipherCharCol1 = (c1 + 1) % 5;
                    cipherCharCol2 = (c2 + 1) % 5;
                }
                //if found 2-character in same column >> choose latter blew each latter
                else if (c1 == c2)
                {
                    cipherCharCol1 = c1;
                    cipherCharCol2 = c2;

                    cipherCharRow1 = (r1 + 1) % 5;
                    cipherCharRow2 = (r2 + 1) % 5;

                }
                //if if found 2-character in different col&row >> take diagonal
                else
                {
                    cipherCharRow1 = r1;
                    cipherCharRow2 = r2;

                    cipherCharCol1 = c2;
                    cipherCharCol2 = c1;
                }

                cText += matrix[cipherCharRow1, cipherCharCol1];
                cText += matrix[cipherCharRow2, cipherCharCol2];


            }
            return cText;
        }

    }
}