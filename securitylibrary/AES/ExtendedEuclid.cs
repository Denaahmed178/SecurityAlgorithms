using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            ///( (b ^ -1) mod m) b>>Number - m>>baseN 
            ///Declare Q and initialize variables, A1, A2,A3 and B1,B2,B3 to store the values
            int Q;
            int A1 = 1, A2 = 0, A3 = baseN;
            int B1 = 0, B2 = 1, B3 = number;

           
            while (B3 > 1)
            {
               ///Calculate the quotient Q by dividing A3 by B3.
                Q = A3 / B3;
                
                ///Calculate the remainder Rn 
                int R1 = A1 - Q * B1;
                int R2 = A2 - Q * B2;
                int R3 = A3 - Q * B3;
                
                ///Update An with the value of Bn
                A1 = B1;
                A2 = B2;
                A3 = B3;
                
                ///Update Bn with the value of reminder Rn
                B1 = R1;
                B2 = R2;
                B3 = R3;
            }

            int Inverse = 0;
            
            /// if B3 is equal to 0, meaning the inverse does not exist
            if (B3 == 0)
            {
                Inverse = -1;
            }
           
            /// if B3 is equal to 1, meaning the inverse exists.
            else if (B3 == 1)
            {
                ///if B2 is negative then the inverse is (-B2 mod baseN)== B2 + baseN
                if (B2 < 0)
                    Inverse = B2 + baseN;
                
                ///if B2 is postive then the inverse is (B2 mod baseN)== B2 
                else
                    Inverse = B2;

            }
            return Inverse;

        }
    }
}