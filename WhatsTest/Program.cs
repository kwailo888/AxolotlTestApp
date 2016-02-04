using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using WhatsAppApi;
using WhatsAppApi.Account;
using WhatsAppApi.Helper;
using WhatsAppApi.Register;
using WhatsAppApi.Response;

namespace WhatsTest
{
    internal class Program
    {
        // DEMO STORE SHOULD BE DATABASE OR PERMANENT MEDIA IN REAL CASE
        static IDictionary<string, axolotl_identities_object> axolotl_identities        = new Dictionary<string, axolotl_identities_object>();
        static IDictionary<uint, axolotl_prekeys_object> axolotl_prekeys                = new Dictionary<uint, axolotl_prekeys_object>();
        static IDictionary<uint, axolotl_sender_keys_object> axolotl_sender_keys        = new Dictionary<uint, axolotl_sender_keys_object>();
        static IDictionary<string, axolotl_sessions_object> axolotl_sessions            = new Dictionary<string, axolotl_sessions_object>();
        static IDictionary<uint, axolotl_signed_prekeys_object> axolotl_signed_prekeys  = new Dictionary<uint, axolotl_signed_prekeys_object>();

        static WhatsApp wa = null;

        private static void Main(string[] args)
        {
            var tmpEncoding = Encoding.UTF8;
            System.Console.OutputEncoding = Encoding.Default;
            System.Console.InputEncoding = Encoding.Default;
            string nickname = "WhatsApiNet";
            string sender = "70178717679"; // Mobile number with country code (but without + or 00)
            string password = "VPU^^^^^^^^^^^^CdM=";//v2 password
            string target = "70125223790";// Mobile number to send the message to

            wa = new WhatsApp(sender, password, nickname, true);

            //event bindings
            wa.OnLoginSuccess += wa_OnLoginSuccess;
            wa.OnLoginFailed += wa_OnLoginFailed;
            wa.OnGetMessage += wa_OnGetMessage;
            wa.OnGetMessageReadedClient += wa_OnGetMessageReadedClient;
            wa.OnGetMessageReceivedClient += wa_OnGetMessageReceivedClient;
            wa.OnGetMessageReceivedServer += wa_OnGetMessageReceivedServer;
            wa.OnNotificationPicture += wa_OnNotificationPicture;
            wa.OnGetPresence += wa_OnGetPresence;
            wa.OnGetGroupParticipants += wa_OnGetGroupParticipants;
            wa.OnGetLastSeen += wa_OnGetLastSeen;
            wa.OnGetTyping += wa_OnGetTyping;
            wa.OnGetPaused += wa_OnGetPaused;
            wa.OnGetMessageImage += wa_OnGetMessageImage;
            wa.OnGetMessageAudio += wa_OnGetMessageAudio;
            wa.OnGetMessageVideo += wa_OnGetMessageVideo;
            wa.OnGetMessageLocation += wa_OnGetMessageLocation;
            wa.OnGetMessageVcard += wa_OnGetMessageVcard;
            wa.OnGetPhoto += wa_OnGetPhoto;
            wa.OnGetPhotoPreview += wa_OnGetPhotoPreview;
            wa.OnGetGroups += wa_OnGetGroups;
            wa.OnGetSyncResult += wa_OnGetSyncResult;
            wa.OnGetStatus += wa_OnGetStatus;
            wa.OnGetPrivacySettings += wa_OnGetPrivacySettings;
            DebugAdapter.Instance.OnPrintDebug += Instance_OnPrintDebug;
            wa.SendGetServerProperties();
            //ISessionStore AxolotlStore
            wa.OnstoreSession += wa_OnstoreSession;
            wa.OnloadSession += wa_OnloadSession;
            wa.OngetSubDeviceSessions += wa_OngetSubDeviceSessions;
            wa.OncontainsSession += wa_OncontainsSession;
            wa.OndeleteSession += wa_OndeleteSession;
            // IPreKeyStore AxolotlStore
            wa.OnstorePreKey += wa_OnstorePreKey;
            wa.OnloadPreKey += wa_OnloadPreKey;
            wa.OnloadPreKeys += wa_OnloadPreKeys;
            wa.OncontainsPreKey += wa_OncontainsPreKey;
            wa.OnremovePreKey += wa_OnremovePreKey;
            // ISignedPreKeyStore AxolotlStore
            wa.OnstoreSignedPreKey += wa_OnstoreSignedPreKey;
            wa.OnloadSignedPreKey += wa_OnloadSignedPreKey;
            wa.OnloadSignedPreKeys += wa_OnloadSignedPreKeys;
            wa.OncontainsSignedPreKey += wa_OncontainsSignedPreKey;
            wa.OnremoveSignedPreKey += wa_OnremoveSignedPreKey;
            // IIdentityKeyStore AxolotlStore
            wa.OngetIdentityKeyPair += wa_OngetIdentityKeyPair;
            wa.OngetLocalRegistrationId += wa_OngetLocalRegistrationId;
            wa.OnisTrustedIdentity += wa_OnisTrustedIdentity;
            wa.OnsaveIdentity += wa_OnsaveIdentity;
            wa.OnstoreLocalData += wa_OnstoreLocalData;
            // Error Notification ErrorAxolotl
            wa.OnErrorAxolotl += wa_OnErrorAxolotl;

            wa.Connect();

            string datFile = getDatFileName(sender);
            byte[] nextChallenge = null;
            if (File.Exists(datFile))
            {
                try
                {
                    string foo = File.ReadAllText(datFile);
                    nextChallenge = Convert.FromBase64String(foo);
                }
                catch (Exception) { };
            }

            wa.Login(nextChallenge);
            wa.SendGetPrivacyList();
            wa.SendGetClientConfig();

            if (wa.LoadPreKeys() == null)
                wa.sendSetPreKeys(true);

            ProcessChat(wa, target);
            Console.ReadKey();
        }

        static void wa_OnGetMessageReadedClient(string from, string id)
        {
            Console.WriteLine("Message {0} to {1} read by client", id, from);
        }

        static void Instance_OnPrintDebug(object value)
        {
            Console.WriteLine(value);
        }

        static void wa_OnGetPrivacySettings(Dictionary<ApiBase.VisibilityCategory, ApiBase.VisibilitySetting> settings)
        {
            throw new NotImplementedException();
        }

        static void wa_OnGetStatus(string from, string type, string name, string status)
        {
            Console.WriteLine(String.Format("Got status from {0}: {1}", from, status));
        }

        static string getDatFileName(string pn)
        {
            string filename = string.Format("{0}.next.dat", pn);
            return Path.Combine(Directory.GetCurrentDirectory(), filename);
        }

        static void wa_OnGetSyncResult(int index, string sid, Dictionary<string, string> existingUsers, string[] failedNumbers)
        {
            Console.WriteLine("Sync result for {0}:", sid);
            foreach (KeyValuePair<string, string> item in existingUsers)
            {
                Console.WriteLine("Existing: {0} (username {1})", item.Key, item.Value);
            }
            foreach(string item in failedNumbers)
            {
                Console.WriteLine("Non-Existing: {0}", item);
            }
        }

        static void wa_OnGetGroups(WaGroupInfo[] groups)
        {
            Console.WriteLine("Got groups:");
            foreach (WaGroupInfo info in groups)
            {
                Console.WriteLine("\t{0} {1}", info.subject, info.id);
            }
        }

        static void wa_OnGetPhotoPreview(string from, string id, byte[] data)
        {
            Console.WriteLine("Got preview photo for {0}", from);
            File.WriteAllBytes(string.Format("preview_{0}.jpg", from), data);
        }

        static void wa_OnGetPhoto(string from, string id, byte[] data)
        {
            Console.WriteLine("Got full photo for {0}", from);
            File.WriteAllBytes(string.Format("{0}.jpg", from), data);
        }

        static void wa_OnGetMessageVcard(ProtocolTreeNode vcardNode, string from, string id, string name, byte[] data)
        {
            Console.WriteLine("Got vcard \"{0}\" from {1}", name, from);
            File.WriteAllBytes(string.Format("{0}.vcf", name), data);
        }

        // string User new
        static void wa_OnGetMessageLocation(ProtocolTreeNode locationNode, string from, string id, double lon, double lat, string url, string name, byte[] preview, string User)
        {
            Console.WriteLine("Got location from {0} ({1}, {2})", from, lat, lon);
            if(!string.IsNullOrEmpty(name))
            {
                Console.WriteLine("\t{0}", name);
            }
            File.WriteAllBytes(string.Format("{0}{1}.jpg", lat, lon), preview);
        }

        static void wa_OnGetMessageVideo(ProtocolTreeNode mediaNode, string from, string id, string fileName, int fileSize, string url, byte[] preview, string name)
        {
            Console.WriteLine("Got video from {0}", from, fileName);
            OnGetMedia(fileName, url, preview);
        }

        // string name new
        static void wa_OnGetMessageAudio(ProtocolTreeNode mediaNode, string from, string id, string fileName, int fileSize, string url, byte[] preview, string name)
        {
            Console.WriteLine("Got audio from {0}", from, fileName);
            OnGetMedia(fileName, url, preview);
        }

        // string name new
        static void wa_OnGetMessageImage(ProtocolTreeNode mediaNode, string from, string id, string fileName, int size, string url, byte[] preview, string name)
        {
            Console.WriteLine("Got image from {0}", from, fileName);
            OnGetMedia(fileName, url, preview);
        }

        static void OnGetMedia(string file, string url, byte[] data)
        {
            //save preview
            File.WriteAllBytes(string.Format("preview_{0}.jpg", file), data);
            //download
            using (WebClient wc = new WebClient())
            {
                wc.DownloadFileAsync(new Uri(url), file, null);
            }
        }

        static void wa_OnGetPaused(string from)
        {
            Console.WriteLine("{0} stopped typing", from);
        }

        static void wa_OnGetTyping(string from)
        {
            Console.WriteLine("{0} is typing...", from);
        }

        static void wa_OnGetLastSeen(string from, DateTime lastSeen)
        {
            Console.WriteLine("{0} last seen on {1}", from, lastSeen.ToString());
        }

        static void wa_OnGetMessageReceivedServer(string from, string id)
        {
            Console.WriteLine("Message {0} to {1} received by server", id, from);
        }

        static void wa_OnGetMessageReceivedClient(string from, string id)
        {
            Console.WriteLine("Message {0} to {1} received by client", id, from);
        }

        static void wa_OnGetGroupParticipants(string gjid, string[] jids)
        {
            Console.WriteLine("Got participants from {0}:", gjid);
            foreach (string jid in jids)
            {
                Console.WriteLine("\t{0}", jid);
            }
        }

        static void wa_OnGetPresence(string from, string type)
        {
            Console.WriteLine("Presence from {0}: {1}", from, type);
        }

        static void wa_OnNotificationPicture(string type, string jid, string id)
        {
            //TODO
            //throw new NotImplementedException();
        }

        static void wa_OnGetMessage(ProtocolTreeNode node, string from, string id, string name, string message, bool receipt_sent)
        {
            Console.WriteLine("Message from {0} {1}: {2}", name, from, message);
        }

        private static void wa_OnLoginFailed(string data)
        {
            Console.WriteLine("Login failed. Reason: {0}", data);
        }

        private static void wa_OnLoginSuccess(string phoneNumber, byte[] data)
        {
            Console.WriteLine("Login success. Next password:");
            string sdata = Convert.ToBase64String(data);
            Console.WriteLine(sdata);
            try
            {
                File.WriteAllText(getDatFileName(phoneNumber), sdata);
            }
            catch (Exception) { }
        }

        private static void ProcessChat(WhatsApp wa, string dst)
        {
            var thRecv = new Thread(t =>
                                        {
                                            try
                                            {
                                                while (wa != null)
                                                {
                                                    wa.PollMessages();
                                                    Thread.Sleep(100);
                                                    continue;
                                                }
                                                    
                                            }
                                            catch (ThreadAbortException)
                                            {
                                            }
                                        }) {IsBackground = true};
            thRecv.Start();

            WhatsUserManager usrMan = new WhatsUserManager();
            var tmpUser = usrMan.CreateUser(dst, "User");

            while (true)
            {
                string line = Console.ReadLine();
                if (line == null && line.Length == 0)
                    continue;

                string command = line.Trim();
                switch (command)
                {
                    case "/query":
                        //var dst = dst//trim(strstr($line, ' ', FALSE));
                        Console.WriteLine("[] Interactive conversation with {0}:", tmpUser);
                        break;
                    case "/accountinfo":
                        Console.WriteLine("[] Account Info: {0}", wa.GetAccountInfo().ToString());
                        break;
                    case "/lastseen":
                        Console.WriteLine("[] Request last seen {0}", tmpUser);
                        wa.SendQueryLastOnline(tmpUser.GetFullJid());
                        break;
                    case "/exit":
                        wa = null;
                        thRecv.Abort();
                        return;
                    case "/start":
                        wa.SendComposing(tmpUser.GetFullJid());
                        break;
                    case "/pause":
                        wa.SendPaused(tmpUser.GetFullJid());
                        break;
                    default:
                        Console.WriteLine("[] Send message to {0}: {1}", tmpUser, line);
                        wa.SendMessage(tmpUser.GetFullJid(), line);
                        break;
                }
           } 
        }

        // ALL NE REQUIRED INTERFACES FOR AXOLOTL ARE BELOW
        /// <summary>
        /// recieve all errormessgaes from the Axolotl process to record
        /// </summary>
        /// <param name="ErrorMessage"></param>
        static void wa_OnErrorAxolotl(string ErrorMessage)
        {
        }

        #region DATABASE BINDING FOR IIdentityKeyStore
        /// <summary>
        /// 
        /// </summary>
        /// <param name="recipientId"></param>
        /// <param name="identityKey"></param>
        static bool wa_OnsaveIdentity(string recipientId, byte[] identityKey)
        {
            if (axolotl_identities.ContainsKey(recipientId))
                axolotl_identities.Remove(recipientId);

            axolotl_identities.Add(recipientId, new axolotl_identities_object(){
                    recipient_id = recipientId,
                    public_key  = identityKey
                });

            return true;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="recipientId"></param>
        /// <param name="identityKey"></param>
        /// <returns></returns>
        static bool wa_OnisTrustedIdentity(string recipientId, byte[] identityKey)
        {
            axolotl_identities_object trusted;
            axolotl_identities.TryGetValue(recipientId, out trusted);
            return true; // (trusted == null || trusted.public_key.Equals(identityKey));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        static uint wa_OngetLocalRegistrationId()
        {
            axolotl_identities_object identity;
            axolotl_identities.TryGetValue("-1", out identity);
            return (identity == null) ? 000000 : uint.Parse(identity.registration_id);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        static List<byte[]> wa_OngetIdentityKeyPair()
        {
            List<byte[]> result = new List<byte[]> { };
            axolotl_identities_object identity;
            axolotl_identities.TryGetValue("-1", out identity);
            if (identity != null){
                result.Add(identity.public_key);
                result.Add(identity.private_key);
            }

            if (result.Count == 0)
                return null;

            return result;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="registrationId"></param>
        /// <param name="identityKeyPair"></param>
        static void wa_OnstoreLocalData(uint registrationId, byte[] publickey, byte[] privatekey)
        {
            if (axolotl_identities.ContainsKey("-1"))
                axolotl_identities.Remove("-1");

            axolotl_identities.Add("-1", new axolotl_identities_object(){
                recipient_id = "-1",
                registration_id = registrationId.ToString(),
                public_key = publickey,
                private_key = privatekey
            });

        }
        #endregion

        #region DATABASE BINDING FOR ISignedPreKeyStore
        /// <summary>
        /// 
        /// </summary>
        /// <param name="preKeyId"></param>
        static void wa_OnremoveSignedPreKey(uint preKeyId)
        {
            if (axolotl_signed_prekeys.ContainsKey(preKeyId))
                axolotl_signed_prekeys.Remove(preKeyId);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="preKeyId"></param>
        /// <returns></returns>
        static bool wa_OncontainsSignedPreKey(uint preKeyId)
        {
            axolotl_signed_prekeys_object prekey;
            axolotl_signed_prekeys.TryGetValue(preKeyId, out prekey);
            return (prekey == null) ? false : true;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        static List<byte[]> wa_OnloadSignedPreKeys()
        {
            List<byte[]> result = new List<byte[]> { };
            foreach (axolotl_signed_prekeys_object key in axolotl_signed_prekeys.Values) 
                result.Add(key.record);

            if (result.Count == 0)
                return null;

            return result;

        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="preKeyId"></param>
        /// <returns></returns>
        static byte[] wa_OnloadSignedPreKey(uint preKeyId)
        {
            axolotl_signed_prekeys_object prekey;
            axolotl_signed_prekeys.TryGetValue(preKeyId, out prekey);
            return (prekey == null) ? new byte[] { } : prekey.record;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="signedPreKeyId"></param>
        /// <param name="signedPreKeyRecord"></param>
        static void wa_OnstoreSignedPreKey(uint signedPreKeyId, byte[] signedPreKeyRecord)
        {
            if (axolotl_signed_prekeys.ContainsKey(signedPreKeyId))
                axolotl_signed_prekeys.Remove(signedPreKeyId);

            axolotl_signed_prekeys.Add(signedPreKeyId, new axolotl_signed_prekeys_object(){
                prekey_id = signedPreKeyId,
                record = signedPreKeyRecord
            });

        }
        #endregion

        #region DATABASE BINDING FOR IPreKeyStore
        /// <summary>
        /// 
        /// </summary>
        /// <param name="preKeyId"></param>
        static void wa_OnremovePreKey(uint preKeyId)
        {
            if (axolotl_prekeys.ContainsKey(preKeyId))
                axolotl_prekeys.Remove(preKeyId);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="preKeyId"></param>
        /// <returns></returns>
        static bool wa_OncontainsPreKey(uint preKeyId)
        {
            axolotl_prekeys_object prekey;
            axolotl_prekeys.TryGetValue(preKeyId, out prekey);
            return (prekey == null) ? false : true;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="preKeyId"></param>
        /// <returns></returns>
        static byte[] wa_OnloadPreKey(uint preKeyId)
        {
            axolotl_prekeys_object prekey;
            axolotl_prekeys.TryGetValue(preKeyId, out prekey);
            return (prekey == null) ? new byte[] { } : prekey.record;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        static List<byte[]> wa_OnloadPreKeys()
        {
            List<byte[]> result = new List<byte[]> { };
            foreach (axolotl_prekeys_object key in axolotl_prekeys.Values)
                result.Add(key.record);

            if (result.Count == 0)
                return null;

            return result;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="prekeyId"></param>
        /// <param name="preKeyRecord"></param>
        static void wa_OnstorePreKey(uint prekeyId, byte[] preKeyRecord)
        {
            if (axolotl_prekeys.ContainsKey(prekeyId))
                axolotl_prekeys.Remove(prekeyId);

            axolotl_prekeys.Add(prekeyId, new axolotl_prekeys_object()
            {
                prekey_id = prekeyId.ToString(),
                record = preKeyRecord
            });
        }
        #endregion

        #region DATABASE BINDING FOR ISessionStore
        /// <summary>
        /// 
        /// </summary>
        /// <param name="recipientId"></param>
        /// <param name="deviceId"></param>
        static void wa_OndeleteSession(string recipientId, uint deviceId)
        {
            if (axolotl_sessions.ContainsKey(recipientId))
                axolotl_sessions.Remove(recipientId);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="recipientId"></param>
        /// <param name="deviceId"></param>
        /// <returns></returns>
        static bool wa_OncontainsSession(string recipientId, uint deviceId)
        {
            axolotl_sessions_object session;
            axolotl_sessions.TryGetValue(recipientId, out session);
            return (session == null) ? false : true;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="recipientId"></param>
        /// <returns></returns>
        static List<uint> wa_OngetSubDeviceSessions(string recipientId)
        {
            List<uint> result = new List<uint> { };
            foreach (axolotl_sessions_object key in axolotl_sessions.Values) 
                    result.Add(key.device_id);

            return result;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="recipientId"></param>
        /// <param name="deviceId"></param>
        /// <returns></returns>
        static byte[] wa_OnloadSession(string recipientId, uint deviceId)
        {
            axolotl_sessions_object session;
            axolotl_sessions.TryGetValue(recipientId, out session);
            return (session == null) ? new byte[] { } : session.record;

        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="recipientId"></param>
        /// <param name="deviceId"></param>
        /// <param name="sessionRecord"></param>
        static void wa_OnstoreSession(string recipientId, uint deviceId, byte[] sessionRecord)
        {

            if (axolotl_sessions.ContainsKey(recipientId))
                axolotl_sessions.Remove(recipientId);

            axolotl_sessions.Add(recipientId, new axolotl_sessions_object(){
                device_id = deviceId,
                recipient_id = recipientId,
                record = sessionRecord
            });
        }
        #endregion
    }

    public class axolotl_identities_object {
        public string recipient_id { get; set; }
        public string registration_id { get; set; }
        public byte[] public_key { get; set; }
        public byte[] private_key { get; set; }
    }
    public class axolotl_prekeys_object {
        public string prekey_id { get; set; }
        public byte[] record { get; set; }

    }
    public class axolotl_sender_keys_object {
        public uint sender_key_id { get; set; }
        public byte[] record { get; set; }
    }
    public class axolotl_sessions_object {
        public string recipient_id { get; set; }
        public uint device_id { get; set; }
        public byte[] record { get; set; }
    }
    public class axolotl_signed_prekeys_object {
        public uint prekey_id { get; set; }
        public byte[] record { get; set; }
    }
}
