using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
       //function for modular exponentiation (a_y^k) mod q
        public static long ModularArithmetic(long a_y, long k, long q)
        {
            // B A S E  C A S E
            if (q == 1)
                return 0;
            if (k == 0)
                return 1 % q;

            // C O N Q U E R
            long sub = ModularArithmetic(a_y, k / 2, q);// R E C U R S I V E

            // C O M B I N E
            long mod = (sub * sub) % q;
            if (k % 2 == 1)
                mod = (mod * a_y) % q;
            return mod;
        }
        //function for modular inverse of (a modulo m) using the extended Euclidean
        public static long ModularInverse(long a, long m)
        {

            long m0 = m;
            long y = 0, x = 1;

            if (m == 1)
                return 0;

            while (a > 1)
            {

                long q = a / m;

                long t = m;

                m = a % m;
                a = t;
                t = y;
                y = x - q * y;
                x = t;
            }
            if (x < 0)
                x += m0;

            return x;
        }
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            ///C1= alpha^k  mod q
            long C1 = ModularArithmetic(alpha, k, q);
            
            ///K = y^k mod q
            ///C2= m*k  mod q
            long C2 = (m * ModularArithmetic(y, k, q)) % q;
            
            /// returns a list containing cipher of( C1 and C2)
            List<long> Cipher = new List<long>();
            Cipher.Add(C1);
            Cipher.Add(C2);
            return Cipher;

        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            ///((c1)^x)mod q==>ModularArithmetic(c1, x, q)
            ///((c1)^x)^-1==>ModularInverse(ModularArithmetic(c1, x, q), q)
            ///plainText = c2* ((c1)^x)^-1 mod q
            long decryptedMessage = (c2 * ModularInverse(ModularArithmetic(c1, x, q), q)) % q;
            ///convert the plaintext from long to int and return it
            return (int)decryptedMessage;

        }
    }
}
