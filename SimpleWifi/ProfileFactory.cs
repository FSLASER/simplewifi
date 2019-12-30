﻿using SimpleWifi.Win32.Interop;
using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;

namespace SimpleWifi
{
    internal static class ProfileFactory
    {
        /// <summary>
        /// Generates the profile XML for the access point and password
        /// </summary>
        internal static string Generate(WlanAvailableNetwork network, string password)
        {
            string profile;
            string template;
            string name = EapUserFactory.EncodeForXML(Encoding.UTF8.GetString(network.dot11Ssid.SSID, 0, (int)network.dot11Ssid.SSIDLength));
            string hex = GetHexString(network.dot11Ssid.SSID);
            string encodedPassword = EapUserFactory.EncodeForXML(password);

            var authAlgo = network.dot11DefaultAuthAlgorithm;

            switch (network.dot11DefaultCipherAlgorithm)
            {
                case Dot11CipherAlgorithm.None:
                    template = GetTemplate("OPEN");
                    profile = string.Format(template, name, hex);
                    break;
                case Dot11CipherAlgorithm.WEP:
                    template = GetTemplate("WEP");
                    profile = string.Format(template, name, hex, encodedPassword);
                    break;
                case Dot11CipherAlgorithm.CCMP:
                    if (authAlgo == Dot11AuthAlgorithm.RSNA)
                    {
                        template = GetTemplate("WPA2-Enterprise-PEAP-MSCHAPv2");
                        profile = string.Format(template, name);
                    }
                    else // PSK
                    {
                        template = GetTemplate("WPA2-PSK");
                        profile = string.Format(template, name, encodedPassword);
                    }
                    break;
                case Dot11CipherAlgorithm.TKIP:
#warning Robin: Not sure WPA uses RSNA
                    if (authAlgo == Dot11AuthAlgorithm.RSNA)
                    {
                        template = GetTemplate("WPA-Enterprise-PEAP-MSCHAPv2");
                        profile = string.Format(template, name);
                    }
                    else // PSK
                    {
                        template = GetTemplate("WPA-PSK");
                        profile = string.Format(template, name, encodedPassword);
                    }

                    break;
                default:
                    throw new NotImplementedException("Profile for selected cipher algorithm is not implemented");
            }

            return profile;
        }

        /// <summary>
        /// Fetches the template for an wireless connection profile.
        /// </summary>
        private static string GetTemplate(string name)
        {
            string resourceName = $"SimpleWifi.ProfileXML.{name}.xml";

            using (var reader = new StreamReader(Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName)))
            {
                return reader.ReadToEnd();
            }
        }

        /// <summary>
        /// Converts an byte array into the hex representation, ex: [255, 255] -> "FFFF"
        /// </summary>
        private static string GetHexString(byte[] ba)
        {
            var sb = new StringBuilder(ba.Length * 2);

            foreach (byte b in ba.TakeWhile(b => b != 0))
            {
                sb.AppendFormat("{0:x2}", b);
            }

            return sb.ToString();
        }
    }
}
