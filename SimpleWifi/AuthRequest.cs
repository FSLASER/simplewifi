using SimpleWifi.Win32;
using SimpleWifi.Win32.Interop;
using System.Text.RegularExpressions;

namespace SimpleWifi
{
	public class AuthRequest
	{
		private readonly bool _isEAPStore;
        private readonly WlanAvailableNetwork _network;
		private readonly WlanInterface _interface;

		public AuthRequest(AccessPoint ap)
		{	
			_network	= ap.Network;
			_interface	= ap.Interface;

			IsPasswordRequired = 
				_network.securityEnabled &&
				_network.dot11DefaultCipherAlgorithm != Dot11CipherAlgorithm.None;

			_isEAPStore =
				_network.dot11DefaultAuthAlgorithm == Dot11AuthAlgorithm.RSNA ||
				_network.dot11DefaultAuthAlgorithm == Dot11AuthAlgorithm.WPA;

			IsUsernameRequired = _isEAPStore;
			IsDomainSupported	= _isEAPStore;
		}
		
		public bool IsPasswordRequired { get; }

        public bool IsUsernameRequired { get; }

        public bool IsDomainSupported { get; }

        public string Password { get; set; }

        public string Username { get; set; }

        public string Domain { get; set; }

        public bool IsPasswordValid
		{
			get
			{
				#warning Robin: Not sure that Enterprise networks have the same requirements on the password complexity as standard ones.
				return PasswordHelper.IsValid(Password, _network.dot11DefaultCipherAlgorithm);
			}
		}
		
		private bool SaveToEAP() 
		{
			if (!_isEAPStore || !IsPasswordValid)
				return false;

			string userXML = EapUserFactory.Generate(_network.dot11DefaultCipherAlgorithm, Username, Password, Domain);
			_interface.SetEAP(_network.profileName, userXML);

			return true;		
		}

		internal bool Process()
		{
			if (!IsPasswordValid)
				return false;
			
			string profileXML = ProfileFactory.Generate(_network, Password);
			_interface.SetProfile(WlanProfileFlags.AllUser, profileXML, true);

			return !_isEAPStore || SaveToEAP();
        }
	}

	public static class PasswordHelper
	{
		/// <summary>
		/// Checks if a password is valid for a cipher type.
		/// </summary>
		public static bool IsValid(string password, Dot11CipherAlgorithm cipherAlgorithm)
		{
			switch (cipherAlgorithm)
			{
				case Dot11CipherAlgorithm.None:
					return true;
				case Dot11CipherAlgorithm.WEP: // WEP key is 10, 26 or 40 hex digits long.
					if (string.IsNullOrEmpty(password))
						return false;

					int len = password.Length;

					bool correctLength = len == 10 || len == 26 || len == 40;
					bool onlyHex = new Regex("^[0-9A-F]+$").IsMatch(password);

					return correctLength && onlyHex;
				case Dot11CipherAlgorithm.CCMP: // WPA2-PSK 8 to 63 ASCII characters					
				case Dot11CipherAlgorithm.TKIP: // WPA-PSK 8 to 63 ASCII characters
					if (string.IsNullOrEmpty(password))
						return false;

					return 8 <= password.Length && password.Length <= 63;
				default:
					return true;
			}
		}
	}
}
