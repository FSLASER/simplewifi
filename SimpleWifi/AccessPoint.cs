namespace SimpleWifi
{
    using System;
    using System.ComponentModel;
    using System.Linq;
    using System.Text;
    using System.Threading;
    using Win32;
    using Win32.Interop;

    public class AccessPoint
	{
        /// <summary>
        /// Returns the underlying network object.
        /// </summary>
        internal WlanAvailableNetwork Network { get; }


        /// <summary>
        /// Returns the underlying interface object.
        /// </summary>
        internal WlanInterface Interface { get; }

        internal AccessPoint(WlanInterface interfac, WlanAvailableNetwork network)
		{
			Interface = interfac;
			Network = network;
		}

		public string Name
		{
			get
			{
				return Encoding.UTF8.GetString(Network.dot11Ssid.SSID, 0, (int)Network.dot11Ssid.SSIDLength);
			}
		}

		public uint SignalStrength
		{
			get
			{
				return Network.wlanSignalQuality;
			}
		}

		/// <summary>
		/// If the computer has a connection profile stored for this access point
		/// </summary>
		public bool HasProfile
		{
			get
			{
				try
				{
					return Interface.GetProfiles().Any(p => p.profileName == Name);
				}
				catch 
				{ 
					return false; 
				}
			}
		}
		
		public bool IsSecure
		{
			get
			{
				return Network.securityEnabled;
			}
		}

		public bool IsConnected
		{
			get
			{
				try
				{
					var a = Interface.CurrentConnection; // This prop throws exception if not connected, which forces me to this try catch. Refactor plix.
					return a.profileName == Network.profileName;
				}
				catch
				{
					return false;
				}
			}
		}

        /// <summary>
        /// Checks that the password format matches this access point's encryption method.
        /// </summary>
        public bool IsValidPassword(string password)
		{
			return PasswordHelper.IsValid(password, Network.dot11DefaultCipherAlgorithm);
		}		
		
		/// <summary>
		/// Connect synchronous to the access point.
		/// </summary>
		public bool Connect(AuthRequest request, bool overwriteProfile = false)
		{
			// No point to continue with the connect if the password is not valid if overwrite is true or profile is missing.
			if (!request.IsPasswordValid && (!HasProfile || overwriteProfile))
				return false;

			// If we should create or overwrite the profile, do so.
			if (!HasProfile || overwriteProfile)
			{				
				if (HasProfile)
					Interface.DeleteProfile(Name);

				request.Process();				
			}

			// TODO: Auth algorithm: IEEE80211_Open + Cipher algorithm: None throws an error.
			// Probably due to connectionmode profile + no profile exist, cant figure out how to solve it though.
			return Interface.ConnectSynchronously(WlanConnectionMode.Profile, Network.dot11BssType, Name, 6000);			
		}

		/// <summary>
		/// Connect asynchronous to the access point.
		/// </summary>
		public void ConnectAsync(AuthRequest request, bool overwriteProfile = false, Action<bool> onConnectComplete = null)
		{
			// TODO: Refactor -> Use async connect in wlaninterface.
			ThreadPool.QueueUserWorkItem(o => {
                bool success;

                try
                {
                    success = Connect(request, overwriteProfile);
                }
                catch (Win32Exception)
                {					
                    success = false;
                }

                onConnectComplete?.Invoke(success);
            });
		}
				
		public string GetProfileXml()
        {
            return HasProfile ? Interface.GetProfileXml(Name) : string.Empty;
        }

		public void DeleteProfile()
		{
			try
			{
				if (HasProfile)
					Interface.DeleteProfile(Name);
			}
            catch
            {
                // ignored
            }
        }

		public sealed override string ToString()
		{
			var info = new StringBuilder();
			info.AppendLine("Interface: " + Interface.InterfaceName);
			info.AppendLine("Auth algorithm: " + Network.dot11DefaultAuthAlgorithm);
			info.AppendLine("Cipher algorithm: " + Network.dot11DefaultCipherAlgorithm);
			info.AppendLine("BSS type: " + Network.dot11BssType);
			info.AppendLine("Connectable: " + Network.networkConnectable);
			
			if (!Network.networkConnectable)
				info.AppendLine("Reason to false: " + Network.wlanNotConnectableReason);

			return info.ToString();
		}
	}
}
