using System.Collections.Generic;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        private int ModPow(int baseValue, int exp, int modulus)
        {
            //calculate modular  exponentiation 
            int result = 1;
            //make loop
            while (exp > 0)
            {
                //and check if less value of power equal one so multiplied
                if (exp % 2 == 1)
                {
                    result = (result * baseValue) % modulus;
                }
                //if bit equal one or not >>make squares the current value of baseValue 
                baseValue = (baseValue * baseValue) % modulus;
                // finally divide exponent by 2 
                exp /= 2;
            }
            return result;
        }
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            //calculate Ya & Yb
            int ya = ModPow(alpha, xa, q);// Ya=alpha power Xa mod q
            int yb = ModPow(alpha, xb, q);// Yb=alpha power Xb mod q

            // Calculate the shared secret keys
            int ka = ModPow(yb, xa, q);// Ka=Yb power Xa mod q 
            int kb = ModPow(ya, xb, q);// Kb=Ya power Xb mod q 

            // Return the keys as a list
            return new List<int> { ka, kb };
        }
    }
}