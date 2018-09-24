﻿using SimpleWifi.Win32.Interop;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;

namespace SimpleWifi
{
    internal static class EapUserFactory
    {
        /// <summary>
        /// Generates the EAP user XML
        /// </summary>
        internal static string Generate(Dot11CipherAlgorithm cipher, string username, string password, string domain)
        {
#warning Robin: Probably not properly implemented, only supports WPA- and WPA-2 Enterprise with PEAP-MSCHAPv2

            string profile = string.Empty;
            string template = string.Empty;

            switch (cipher)
            {
                case Dot11CipherAlgorithm.CCMP: // WPA-2
                case Dot11CipherAlgorithm.TKIP: // WPA
                    template = GetTemplate("PEAP-MS-CHAPv2");

                    profile = string.Format(
                        template,
                        EncodeForXML(username, true),
                        EncodeForXML(password, true),
                        EncodeForXML(domain, true));
                    break;
                default:
                    throw new NotImplementedException("Profile for selected cipher algorithm is not implemented");
            }

            return profile;
        }

        /// <summary>
        /// Fetches the template for an EAP user
        /// </summary>
        private static string GetTemplate(string name)
        {
            string resourceName = string.Format("SimpleWifi.EapUserXML.{0}.xml", name);

            using (StreamReader reader = new StreamReader(Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName)))
            {
                return reader.ReadToEnd();
            }
        }

        internal static string EncodeForXML(string toxml, bool base64 = false)
        {
            if (!string.IsNullOrEmpty(toxml))
            {
                if (base64)
                {
                    toxml = EncodeToBase64(toxml);
                }

                toxml = toxml.Replace("&", "&#038;");
                toxml = toxml.Replace("<", "&#060;");
                toxml = toxml.Replace(">", "&#062;");
                toxml = toxml.Replace("'", "&apos;");
                toxml = toxml.Replace("\"", "&quot;");
            }

            return toxml;
        }

        private static string EncodeToBase64(string toEncode)
        {
            byte[] toEncodeAsBytes = System.Text.ASCIIEncoding.ASCII.GetBytes(toEncode);
            string returnValue = System.Convert.ToBase64String(toEncodeAsBytes);
            return returnValue;
        }
    }
}
