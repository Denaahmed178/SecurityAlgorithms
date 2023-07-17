using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        
        ///function to calculate B^P mod N in large numbers
        public static long ModOfPower(long B, long P, long M) 
        {

            if (B == 0 || M == 0)
                return 0;
            if (P == 0)
                return 1;
            if (P == 1)
                return B % M;

            long R = ModOfPower(B, P / 2, M);
            if (P % 2 == 0)
            {
                R *= R;
                R %= M;
            }
            else
            {
                R *= R;
                R *= B;
                R %= M;
            }

            R %= M;
            return R;

        }

        ///function to calculate Euclidean Algorithm (GCD)
        public int GCD(int a, int b)
        {
            while (a != 0 && b != 0)
            {
                if (a > b)
                    a %= b;
                else
                    b %= a;
            }

            return a | b;
        }
        public int Encrypt(int p, int q, int M, int e)
        {
            bool flag = false;
            ///  n = pq and n will be half of the public key
            int n = p * q;

            ///ϕ(n)==(p - 1) * (q - 1)
            int phiN = (p - 1) * (q - 1);
            
            /// check if e is  relatively prime
            for (int i = 0; i < phiN; i++)
            {
                ///if the GCD==1 then e is relatively prime to ϕ(n)
                ///e will be the other half of the public key
                if (GCD(e, phiN) == 1)
                {
                    flag = true;
                    break;
                }
            }
            ///public key KUB{n,e}  and plaintext M 


            ///if e is relatively prime
            int cipher = 0;
            if (flag == true)
            {
                ///plaintext must be less than n.
                if (M < n)
                   ///calculate ciphertext= M^e mod n  
                   ///then convert it from long to int 
                    cipher = Convert.ToInt32(ModOfPower(M, e, n));
            }
            return cipher;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            bool flag = false;
            
            ///  n = pq 
            int n = p * q;
           
            ///ϕ(n)==(p - 1) * (q - 1)
            int phin = (p - 1) * (q - 1);
            
            /// check if e is  relatively prime
            for (int i = 0; i < phin; i++) {
                ///if the GCD==1 then e is relatively prime to ϕ(n)
                if (GCD(e, phin) == 1)
                {
                    flag = true;
                    break; 
                }
    
            }


            ///if e is relatively prime
            int M=0;
            if (flag == true)
            {  
                var obj = new AES.ExtendedEuclid();
                ///calculate Extended Euclidean of d =e^-1 mod ϕ(n)
                int d = obj.GetMultiplicativeInverse(e, phin);
                ///private key KRb{d,p,q}  and Ciphertext C
                
                ///calculate plaintext(M)= M^e mod n  
                ///then convert it from long to int 
                M = Convert.ToInt32(ModOfPower(C, d, n));
            }
            return M;
        }
    }
}
