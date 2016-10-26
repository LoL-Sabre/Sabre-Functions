using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using System.Data.HashFunction;
using System.Text.RegularExpressions;

namespace Functions
{
    public class Functions
    {
        public static int[] WADPublicKey = {
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 
            0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 
            0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x01, 0xE7, 0x1B, 
            0xDD, 0x1D, 0x2F, 0xF5, 0x9C, 0x70, 0x8C, 0xEC, 0xAA, 0xE2, 
            0x5D, 0xB4, 0xDB, 0x85, 0x50, 0x6D, 0x6B, 0x06, 0xED, 0x3B, 
            0xE6, 0x21, 0xF8, 0x1A, 0xD4, 0x85, 0xFD, 0x68, 0x18, 0x8E, 
            0xC5, 0x6B, 0xE1, 0x4E, 0x69, 0x00, 0x8C, 0x69, 0xDE, 0x66, 
            0xF8, 0x16, 0x9F, 0xF3, 0xB2, 0xF5, 0x38, 0x6B, 0x67, 0xB1, 
            0xF1, 0xBE, 0x96, 0x92, 0x04, 0x88, 0x89, 0xEF, 0x3E, 0xE0, 
            0x2B
        };
        public static uint BinHash(string stringToHash)
        {
            stringToHash = stringToHash.ToLower();
            uint hash = 2166136261;
            for (int i = 0; i < stringToHash.Length; i++)
            {
                hash = hash ^ stringToHash[i];
                hash = hash * 16777619;
            }
            return hash;
        }
        public static uint InibinHash(string section, string value)
        {
            uint hash = 0;

            foreach (var c in section.ToLower())
            {
                hash = c + 65599 * hash;
            }
            hash = (65599 * hash + 42);
            foreach (var c in value.ToLower())
            {
                hash = c + 65599 * hash;
            }
            return hash;
        }
        public static uint RafHash(string stringToHash)
        {
            uint hash = 0;
            uint temp = 0;
            for(int i = 0; i < stringToHash.Length; i++)
            {
                hash = (hash << 4) + stringToHash.ToLower()[i];
                if(0 != (temp = (hash & 0xF0000000)))
                {
                    hash = hash ^ (temp >> 24);
                    hash = hash ^ temp;
                }
            }
            return hash;
        }
        public static uint SabreHash(string stringToHash)
        {
            uint hash = 2486;
            string alphabeth = "abcdefghijklmnopqrstuvwxyz0123456789-_";
            char[] charString = stringToHash.ToCharArray();
            stringToHash = stringToHash.ToLower();
            if(stringToHash != "")
            {
                for(int i = 0; i < stringToHash.Length; i++)
                {
                    hash = hash ^ stringToHash[i];
                    foreach(Match m in Regex.Matches(alphabeth, Convert.ToString(charString[i])))
                    {
                        if(m.Success)
                        {
                            hash *= (uint)m.Index;
                        }
                    }
                }
            }
            return hash;
        }
        public static string Md5(string stringToHash)
        {
            StringBuilder sb = new StringBuilder();
            byte[] hash = Encoding.ASCII.GetBytes(stringToHash);
            MD5 md5 = MD5.Create();
            hash = md5.ComputeHash(hash);
            for(int i = 0; i < hash.Length; i++)
            {
                sb.Append(hash[i].ToString("X2"));
            }
            return sb.ToString();
        }
        public static byte[] Sha256(string hashInput)
        {
            System.Security.Cryptography.SHA256 sha256 = new System.Security.Cryptography.SHA256Managed();
            byte[] hash;
            hash = Encoding.ASCII.GetBytes(hashInput);
            hash = sha256.ComputeHash(hash);
            return hash;
        }
        public static byte[] XXHash(string stringToHash)
        {
            byte[] hash;
            xxHash xx = new xxHash();
            hash = xx.ComputeHash(Encoding.ASCII.GetBytes(stringToHash));
            return hash;
        }
        public static byte[] ECDSA(byte[] dataToSign)
        {
            Blob blob = new Blob();
            ECDsaCng dsa = new ECDsaCng(256); //dsa = Digital Signature Algorithm
            blob.key = dsa.Key.Export(CngKeyBlobFormat.EccPublicBlob);
            byte[] signature = dsa.SignData(dataToSign);
            blob.Receive(dataToSign, signature);
            return signature;
        } //WAD Header usage, Public key = WADPublicKey

        public static string GetStringFromChars(char[] chars)
        {
            string final = "";
            int i = 0;
            while (i < chars.Length && chars[i] != 0)
            {
                final += chars[i];
                i++;
            }
            return final;
        }
        public static char[] GetCharsFromString(string str, int size)
        {
            char[] final = new char[size];
            int i = 0;
            while (i < size && i < str.Length)
            {
                final[i] = str[i];
                i++;
            }
            return final;
        }

        public static double CompressXRGBAColor(double color)
        {
            double db;
            db = color / 255;
            return db;
        }
        public static double DecompressXRGBAColor(double color)
        {
            double db;
            db = color * 255;
            db = Math.Round(db);
            return db;
        }

        public static int[] Vector2(int x, int y)
        {
            int[] vector = new int[2];
            vector[0] = x;
            vector[1] = y;
            return vector;
        }
        public static int[] Vector3(int x, int y, int z)
        {
            int[] vector = new int[3];
            vector[0] = x;
            vector[1] = y;
            vector[2] = z;
            return vector;
        }
        public static int[] Vector4(int x, int y, int z, int w)
        {
            int[] vector = new int[4];
            vector[0] = x;
            vector[1] = y;
            vector[2] = z;
            vector[3] = w;
            return vector;
        }

        public static float[] FloatVector2(float x, float y)
        {
            float[] vector = new float[2];
            vector[0] = x;
            vector[1] = y;
            return vector;
        }
        public static float[] FloatVector3(float x, float y, float z)
        {
            float[] vector = new float[3];
            vector[0] = x;
            vector[1] = y;
            vector[2] = z;
            return vector;
        }
        public static float[] FloatVector4(float x, float y, float z, float w)
        {
            float[] vector = new float[4];
            vector[0] = x;
            vector[1] = y;
            vector[2] = z;
            vector[3] = w;
            return vector;
        }

        public static double[] XRGBAVector(double time, double r, double g, double b, double a)
        {
            double[] vector = new double[5];
            vector[0] = time;
            vector[1] = r;
            vector[2] = g;
            vector[3] = b;
            vector[4] = a;
            return vector;
        }

        public class Blob
        {
            public byte[] key;
            public void Receive(byte[] data, byte[] signature)
            {
                using (ECDsaCng ecsdKey = new ECDsaCng(CngKey.Import(key, CngKeyBlobFormat.EccPublicBlob)))
                {
                    if (ecsdKey.VerifyData(data, signature))
                        Console.WriteLine("Data is good");
                    else
                        Console.WriteLine("Data is bad");
                }
            }
        }
    }
}
