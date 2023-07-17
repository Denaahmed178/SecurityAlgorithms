using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            //convert CT & key  to binary
            string CT = Convert.ToString(Convert.ToInt64(cipherText, 16), 2).PadLeft(64, '0');
            string Key1 = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');

            //For Key
            int[,] PC_1 = new int[8, 7] { { 57, 49, 41, 33, 25, 17, 9 },
                { 1, 58, 50, 42, 34, 26, 18 },
                { 10, 2, 59, 51, 43, 35, 27 },
                { 19, 11, 3, 60, 52, 44, 36 },
                { 63, 55, 47, 39, 31, 23, 15 },
                { 7, 62, 54, 46, 38, 30, 22 },
                { 14, 6, 61, 53, 45, 37, 29 },
                { 21, 13, 5, 28, 20, 12, 4 } };
            int[,] PC_2 = new int[8, 6] { { 14, 17, 11, 24, 1, 5 },
                { 3, 28, 15, 6, 21, 10 },
                { 23, 19, 12, 4, 26, 8 },
                { 16, 7, 27, 20, 13, 2 },
                { 41, 52, 31, 37, 47, 55 },
                { 30, 40, 51, 45, 33, 48 },
                { 44, 49, 39, 56, 34, 53 },
                { 46, 42, 50, 36, 29, 32 } };
            int[,] s1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
            int[,] s2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
            int[,] s3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
            int[,] s4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
            int[,] s5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
            int[,] s6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
            int[,] s7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
            int[,] s8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };
            int[,] P = new int[8, 4] { { 16, 7, 20, 21 }, { 29, 12, 28, 17 },
                { 1, 15, 23, 26 },
                { 5, 18, 31, 10 },
                { 2, 8, 24, 14 },
                { 32, 27, 3, 9 },
                { 19, 13, 30, 6 },
                { 22, 11, 4, 25 } };
            int[,] E_BIT = new int[8, 6] { { 32, 1, 2, 3, 4, 5 }, { 4, 5, 6, 7, 8, 9 }, { 8, 9, 10, 11, 12, 13 }, { 12, 13, 14, 15, 16, 17 }, { 16, 17, 18, 19, 20, 21 }, { 20, 21, 22, 23, 24, 25 }, { 24, 25, 26, 27, 28, 29 }, { 28, 29, 30, 31, 32, 1 } };
            //For PT
            int[,] IP = new int[8, 8] { { 58, 50, 42, 34, 26, 18, 10, 2 },
                { 60, 52, 44, 36, 28, 20, 12, 4 },
                { 62, 54, 46, 38, 30, 22, 14, 6 },
                { 64, 56, 48, 40, 32, 24, 16, 8 },
                { 57, 49, 41, 33, 25, 17, 9, 1 },
                { 59, 51, 43, 35, 27, 19, 11, 3 },
                { 61, 53, 45, 37, 29, 21, 13, 5 },
                { 63, 55, 47, 39, 31, 23, 15, 7 } };
            int[,] IP_inverse = new int[8, 8] { { 40, 8, 48, 16, 56, 24, 64, 32 },
                { 39, 7, 47, 15, 55, 23, 63, 31 },
                { 38, 6, 46, 14, 54, 22, 62, 30 },
                { 37, 5, 45, 13, 53, 21, 61, 29 },
                { 36, 4, 44, 12, 52, 20, 60, 28 },
                { 35, 3, 43, 11, 51, 19, 59, 27 },
                { 34, 2, 42, 10, 50, 18, 58, 26 },
                { 33, 1, 41, 9, 49, 17, 57, 25 } };

            //pc-1 for key >>input key 48 bits 
            string NewKey = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 7; j++)
                {
                    NewKey += Key1[PC_1[i, j] - 1];

                }
            }

            //divide NewKey to C&D
            string c = NewKey.Substring(0, 28);
            string d = NewKey.Substring(28, 28);

            //for 16 c&d make shift left
            string store = "";
            List<string> C0 = new List<string>();
            List<string> D0 = new List<string>();

            //create sixteen blocks Cn and Dn >>16 round for c & d
            for (int i = 0; i <= 16; i++)
            {
                C0.Add(c);
                D0.Add(d);
                store = "";
                //make shift-left for specific iteration number 
                if (i == 0 || i == 1 || i == 8 || i == 15)
                {
                    store += c[0];
                    c = c.Remove(0, 1);
                    c += store;
                    store = "";

                    store += d[0];
                    d = d.Remove(0, 1);
                    d += store;

                }
                else
                {
                    store += c.Substring(0, 2);
                    c = c.Remove(0, 2);
                    c += store;
                    store = "";//ok
                    store += d.Substring(0, 2);
                    d = d.Remove(0, 2);
                    d += store;

                }

            }

            // add c&d in another key  result>>(16 key)

            List<string> Kadd = new List<string>();
            for (int j = 0; j < C0.Count; j++)
            {
                Kadd.Add(C0[j] + D0[j]);
            }


            //2-make pc2 for 16 key >>output 48-bit
            List<string> FinalKey = new List<string>();
            for (int x = 1; x < Kadd.Count; x++)
            {
                NewKey = "";//ok
                store = "";//ok
                store = Kadd[x];//ok
                for (int i = 0; i < 8; i++)
                {
                    for (int j = 0; j < 6; j++)
                    {
                        NewKey += store[PC_2[i, j] - 1];//ok
                    }
                }
                FinalKey.Add(NewKey);



              
            }
           

            //IP for CT
            string Npt = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    Npt += CT[IP[i, j] - 1];
                }
            }


            //divide into 32-bit right & 32-bit left
            string leftpt = Npt.Substring(0, 32);
            string rightpt = Npt.Substring(32, 32);


            string e = "";
            string xor = "";
            string fxor = "";
            //make e-bit for 16-right 32>>48  but reverse encrypt
            for (int r = 15; r >= 0; r--)
            {

                e = "";
                xor = "";
                fxor = "";
                for (int i = 0; i < 8; i++)
                {

                    for (int j = 0; j < 6; j++)
                    {
                        e += rightpt[E_BIT[i, j] - 1];
                    }

                }

                //key xor e-bit
                for (int i = 0; i < e.Length; i++)
                {

                    if (e[i] == FinalKey[r][i])
                        xor += "0";
                    else
                        xor += "1";

                }

                //divide into 8-box >s-box
                string b1 = xor.Substring(0, 6);
                string b2 = xor.Substring(6, 6);
                string b3 = xor.Substring(12, 6);
                string b4 = xor.Substring(18, 6);
                string b5 = xor.Substring(24, 6);
                string b6 = xor.Substring(30, 6);
                string b7 = xor.Substring(36, 6);
                string b8 = xor.Substring(42, 6);
                List<string> listB = new List<string>() { b1, b2, b3, b4, b5, b6, b7, b8 };
                List<int[,]> lists = new List<int[,]>() { s1, s2, s3, s4, s5, s6, s7, s8 };
                string str = "";
                string finalsbox = "";

                for (int j = 0; j < listB.Count(); j++)
                {
                    int row = Convert.ToInt32(string.Format("{0}", (listB[j][0].ToString() + listB[j][5])), 2);
                    int col = Convert.ToInt32((listB[j][1].ToString() + listB[j][2] + listB[j][3] + listB[j][4]), 2);
                    str = Convert.ToString(lists[j][row, col], 2).PadLeft(4, '0');
                    finalsbox += str;

                }

                //permutation_P with matrix 8*4 of f
                string func = "";
                for (int i = 0; i < 8; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        func += finalsbox[P[i, j] - 1];
                    }
                }

                //xor_2
                for (int i = 0; i < func.Length; i++)
                {

                    if (func[i] == leftpt[i])
                        fxor += "0";
                    else
                        fxor += "1";

                }
                leftpt = rightpt;
                rightpt = fxor;
            }
            string pt = "";
            //final step swap R&L
            string result = rightpt + leftpt;
            //make inverse ip with matrix 8*8
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    pt += result[IP_inverse[i, j] - 1];


                }

            }
            //finally convert PT to hexadecimal
            pt = "0x" + Convert.ToInt64(pt, 2).ToString("X").PadLeft(16, '0');
            return pt;
        }

        public override string Encrypt(string plainText, string key)
        {
            

            //convert PT & key  to binary
            string PT = Convert.ToString(Convert.ToInt64(plainText, 16), 2).PadLeft(64, '0');
            string Key1 = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');

            //pc-1 For Key
            int[,] PC_1 = new int[8, 7] { { 57, 49, 41, 33, 25, 17, 9 },
                { 1, 58, 50, 42, 34, 26, 18 },
                { 10, 2, 59, 51, 43, 35, 27 },
                { 19, 11, 3, 60, 52, 44, 36 },
                { 63, 55, 47, 39, 31, 23, 15 },
                { 7, 62, 54, 46, 38, 30, 22 },
                { 14, 6, 61, 53, 45, 37, 29 },
                { 21, 13, 5, 28, 20, 12, 4 } };
            int[,] PC_2 = new int[8, 6] { { 14, 17, 11, 24, 1, 5 },
                { 3, 28, 15, 6, 21, 10 },
                { 23, 19, 12, 4, 26, 8 },
                { 16, 7, 27, 20, 13, 2 },
                { 41, 52, 31, 37, 47, 55 },
                { 30, 40, 51, 45, 33, 48 },
                { 44, 49, 39, 56, 34, 53 },
                { 46, 42, 50, 36, 29, 32 } };
            int[,] s1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
            int[,] s2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
            int[,] s3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
            int[,] s4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
            int[,] s5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
            int[,] s6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
            int[,] s7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
            int[,] s8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };
            int[,] P = new int[8, 4] { { 16, 7, 20, 21 }, { 29, 12, 28, 17 },
                { 1, 15, 23, 26 },
                { 5, 18, 31, 10 },
                { 2, 8, 24, 14 },
                { 32, 27, 3, 9 },
                { 19, 13, 30, 6 },
                { 22, 11, 4, 25 } };
            int[,] E_BIT = new int[8, 6] { { 32, 1, 2, 3, 4, 5 }, { 4, 5, 6, 7, 8, 9 }, { 8, 9, 10, 11, 12, 13 }, { 12, 13, 14, 15, 16, 17 }, { 16, 17, 18, 19, 20, 21 }, { 20, 21, 22, 23, 24, 25 }, { 24, 25, 26, 27, 28, 29 }, { 28, 29, 30, 31, 32, 1 } };
            //For PT
            int[,] IP = new int[8, 8] { { 58, 50, 42, 34, 26, 18, 10, 2 },
                { 60, 52, 44, 36, 28, 20, 12, 4 },
                { 62, 54, 46, 38, 30, 22, 14, 6 },
                { 64, 56, 48, 40, 32, 24, 16, 8 },
                { 57, 49, 41, 33, 25, 17, 9, 1 },
                { 59, 51, 43, 35, 27, 19, 11, 3 },
                { 61, 53, 45, 37, 29, 21, 13, 5 },
                { 63, 55, 47, 39, 31, 23, 15, 7 } };
            int[,] IP_inverse = new int[8, 8] { { 40, 8, 48, 16, 56, 24, 64, 32 },
                { 39, 7, 47, 15, 55, 23, 63, 31 },
                { 38, 6, 46, 14, 54, 22, 62, 30 },
                { 37, 5, 45, 13, 53, 21, 61, 29 },
                { 36, 4, 44, 12, 52, 20, 60, 28 },
                { 35, 3, 43, 11, 51, 19, 59, 27 },
                { 34, 2, 42, 10, 50, 18, 58, 26 },
                { 33, 1, 41, 9, 49, 17, 57, 25 } };

            //pc-1 for key >>input key 48 bits 
            string NewKey = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 7; j++)
                {
                    NewKey += Key1[PC_1[i, j] - 1];//output 56 bit

                }
            }
            //divide NewKey to C&D 
            string c = NewKey.Substring(0, 28);
            string d = NewKey.Substring(28, 28);

            //for 16 c&d make shift left
            string store = "";
            List<string> C0 = new List<string>();
            List<string> D0 = new List<string>();

            //create sixteen blocks Cn and Dn >>16 round for c & d
            for (int i = 0; i <= 16; i++)
            {
                C0.Add(c);
                D0.Add(d);
                store = "";
                //make shift-left for specific iteration number 
                if (i == 0 || i == 1 || i == 8 || i == 15)
                {
                    store += c[0];
                    c = c.Remove(0, 1);
                    c += store;
                    store = "";//ok

                    store += d[0];
                    d = d.Remove(0, 1);
                    d += store;

                }
                else
                {
                    store += c.Substring(0, 2);
                    c = c.Remove(0, 2);
                    c += store;
                    store = "";
                    store += d.Substring(0, 2);
                    d = d.Remove(0, 2);
                    d += store;

                }

            }
            // add c&d in another key  result>>(16 key)
            List<string> Kadd = new List<string>();
            for (int j = 0; j < C0.Count; j++)
            {
                Kadd.Add(C0[j] + D0[j]);
            }
            //2-make pc2 for 16 key >>output 48-bit
            List<string> FinalKey = new List<string>();
            for (int x = 1; x < Kadd.Count; x++)
            {
                NewKey = "";
                store = "";
                store = Kadd[x];
                for (int i = 0; i < 8; i++)
                {
                    for (int j = 0; j < 6; j++)
                    {
                        NewKey += store[PC_2[i, j] - 1];
                    }
                }

                FinalKey.Add(NewKey);
            }
                // make IP for PT
                string Npt = "";
                for (int i = 0; i < 8; i++)
                {
                    for (int j = 0; j < 8; j++)
                    {
                        Npt += PT[IP[i, j] - 1];
                    }
                }


                //divide into 32-bit right & 32-bit left
                string leftpt = Npt.Substring(0, 32);
                string rightpt = Npt.Substring(32, 32);
                string e = "";
                string xor = "";
                string fxor = "";
                //make e-bit for 16-right 32>>48 
                for (int r = 0; r <= 15; r++)
                {

                    e = "";
                    xor = "";
                    fxor = "";
                    for (int i = 0; i < 8; i++)
                    {

                        for (int j = 0; j < 6; j++)
                        {
                            e += rightpt[E_BIT[i, j] - 1];
                        }

                    }

                    //key XOR e-bit
                    for (int i = 0; i < e.Length; i++)
                    {

                        if (e[i] == FinalKey[r][i])
                            xor += "0";
                        else
                            xor += "1";

                    }

                    //divide into 8-box >s-box
                    string b1 = xor.Substring(0, 6);
                    string b2 = xor.Substring(6, 6);
                    string b3 = xor.Substring(12, 6);
                    string b4 = xor.Substring(18, 6);
                    string b5 = xor.Substring(24, 6);
                    string b6 = xor.Substring(30, 6);
                    string b7 = xor.Substring(36, 6);
                    string b8 = xor.Substring(42, 6);
                    List<string> listB = new List<string>() { b1, b2, b3, b4, b5, b6, b7, b8 };
                    List<int[,]> lists = new List<int[,]>() { s1, s2, s3, s4, s5, s6, s7, s8 };
                    string str = "";
                    string finalsbox = "";

                    for (int j = 0; j < listB.Count(); j++)
                    {
                        int row = Convert.ToInt32(string.Format("{0}", (listB[j][0].ToString() + listB[j][5])), 2);
                        int col = Convert.ToInt32((listB[j][1].ToString() + listB[j][2] + listB[j][3] + listB[j][4]), 2);
                        str = Convert.ToString(lists[j][row, col], 2).PadLeft(4, '0');
                        finalsbox += str;

                    }


                    //permutation_P  with matrix 8*4 of f
                    string func = "";
                    for (int i = 0; i < 8; i++)
                    {
                        for (int j = 0; j < 4; j++)
                        {
                            func += finalsbox[P[i, j] - 1];
                        }
                    }
                    //xor_2
                    for (int i = 0; i < func.Length; i++)
                    {

                        if (func[i] == leftpt[i])
                            fxor += "0";
                        else
                            fxor += "1";

                    }

                    leftpt = rightpt;
                    rightpt = fxor;
                }


                string ct = "";
                //final step swap R&L
                string result = rightpt + leftpt;
                //make inverse ip with matrix 8*8
                for (int i = 0; i < 8; i++)
                {
                    for (int j = 0; j < 8; j++)
                    {
                        ct += result[IP_inverse[i, j] - 1];


                    }

                }
                //finally convert CT to hexadecimal
                ct = "0x" + Convert.ToInt64(ct, 2).ToString("X").PadLeft(16, '0');
                return ct;


            }
        }
    }

