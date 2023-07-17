using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string alpha = "abcdefghijklmnopqrstuvwxyz";
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            ///// sorted by the key 
            SortedDictionary<char, char> map = new SortedDictionary<char, char>();  

            /* fill the map dictionary  as the dictionary contains the plaintext letter  as key 
             and corresponding cipherletter as value  */
            for (int i = 0; i < plainText.Length && i < cipherText.Length; i++)
            {
                if (!map.ContainsKey(plainText[i])) // to add new letters
                {
                    map.Add(plainText[i], cipherText[i]);
                }
            }
            /* to add the remaining letters of the alphabet that does not appear in the dictionary map as key
               with its corresponding letters that does not appear as value*/
            for (int i = 0; i < alpha.Length; i++)
            {
                if (!map.ContainsKey(alpha[i]))
                {
                    for (int j = 0; j < alpha.Length; j++)
                    {
                        if (!map.ContainsValue(alpha[j]))
                        {
                            map.Add(alpha[i], alpha[j]);
                            j = 26;
                        }

                    }
                }
            }

            string key = "";
            /// fill the string key with the final permutation
            foreach (var item in map)
            {
                key += item.Value;
            }
            /// It trims any leading or trailing whitespace and converts the string to lowercase before returning it.
            return key.Trim().ToLower();
        }

        public string Decrypt(string cipherText, string key)
        {
            
            Dictionary<char, char> keys = new Dictionary<char, char>();

            ///fill the dictionary with the alphabet letters as the key dictionary
            ///the value dictionary is the input key letter
            int j = 0;
            for (char i = 'a'; i <= 'z'; i++, j++)
            {
                keys[i] = key[j];
            }

            String plain = "";
            cipherText = cipherText.ToLower();
            for (int i = 0; i < cipherText.Length; i++)
            {
                foreach (var it in keys)
                {
                    /// if the current cipher character found in the dictionary as a value 
                    if (cipherText[i] == it.Value)
                    {
                        ///append the corresponding key character  to the "plain" string
                        plain += it.Key;
                       
                    }

                }
            }
            return plain;
        }

        public string Encrypt(string plainText, string key)
        {
            
            Dictionary<char, char> keys = new Dictionary<char, char>();
            int j = 0;
            ///This for loop iterates through each character in the English alphabet  
            for (char i = 'a'; i <= 'z'; i++, j++)
            {
        /// creating a mapping between each character in alphabet and its corresponding character in the input key.
                keys[i] = key[j];
            }
            String cipher = "";

            //////For each plaintext character, loop through each key-value pair in the "keys" dictionary.
            for (int i = 0; i < plainText.Length; i++)
            {   
                foreach (var it in keys)
                {
                    /// if the current plaintext character found in the dictionary as a value   
                    if (plainText[i] == it.Key)
                    {
                        ///append the corresponding ciphertext character to the "cipher" string
                        cipher += keys[plainText[i]];
                    }

                }
            }
            // returns the resulting ciphertext string
            return cipher.ToUpper();
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {

            ///English alphabet ordered by letter frequency
            String frequency = "zqjxkvbywgpfmucdlhrsnioate";
            Dictionary<char, int> letterFreq = new Dictionary<char, int>();
            ///For each character, it checks if it is already in the "letterFreq" dictionary.
            for (int i = 0; i < cipher.Length; i++)
            {
                /// it is not exist, it adds an entry with a value of 1.
                if (!(letterFreq.ContainsKey(cipher[i])))
                {
                    letterFreq.Add(cipher[i], 1);
                }
                /// it is in the dictionary, it increments the existing value by 1
                else if (letterFreq.ContainsKey(cipher[i])==true)
                {
                    letterFreq[cipher[i]] += 1;
                }
            }
            ///This line sorts the letterFreq dictionary by its values (frequencies) in ascending order and assigns
            var sortedDict = letterFreq.OrderBy(x => x.Value).ToDictionary(x => x.Key, x => x.Value);
            string plaintxt = cipher;
            for (int index = 0; index < sortedDict.Count(); index++)
            {
                /// replace each character in the plaintxt string with its corresponding character in the frequency string, 
                var dic = sortedDict.ElementAt(index);
                plaintxt = plaintxt.Replace(dic.Key, frequency[index]);
            }
            return plaintxt;
        }
    }
}