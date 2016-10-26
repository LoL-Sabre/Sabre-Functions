using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Functions;

namespace Tester
{
    class Program
    {
        static void Main(string[] args)
        {
            string input;
            string[] inp;
            input = Console.ReadLine();
            inp = input.Split(' ');
            if(inp[0] == "SabreHashTest")
            {
                for(int i = 0; i < Convert.ToUInt32(inp[1]); i++)
                {
                    Console.WriteLine("SabreHashTest" + i + " = " + Functions.Functions.SabreHash("SabreHashTest" + i));
                }
                Console.ReadLine();
            }
            else if(inp[0] == "PUBKEY")
            {
                string key = "";
                foreach(int i in Functions.Functions.WADPublicKey)
                {
                    key += i;
                }
                Console.WriteLine(key);
                Console.ReadLine();
            }
            else if(inp[0] == "MD5")
            {
                Console.WriteLine(Functions.Functions.Md5(inp[1]));
                Console.ReadLine();
            }
        }
    }
}
