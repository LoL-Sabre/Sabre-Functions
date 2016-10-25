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
            return hash;
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
        } //WAD Header usage, Public key unknown

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
