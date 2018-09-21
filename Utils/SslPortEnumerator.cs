using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

class SslPortEnumerator
{
    private Dictionary<int, String> _sslPortsDictionary = new Dictionary<int, string>() {
//        { 261, "IIOP Name Service over TLS/SSL" },
        { 443, "http protocol over TLS/SSL" },
//        { 448, "DDM-SSL" },
        { 465, "smtp protocol over TLS/SSL" },
//        { 563, "nntp protocol over TLS/SSL" },
//        { 614, "SSLshell" },
//        { 636, "ldap protocol over TLS/SSL" },
//        { 989, "ftp protocol, data, over TLS/SSL" },
//        { 990, "ftp, control, over TLS/SSL" },
//        { 992, "telnet protocol over TLS/SSL" },
        { 993, "imap4 protocol over TLS/SSL" },
//        { 994, "irc protocol over TLS/SSL" },
        { 995, "pop3 protocol over TLS/SSL" }
    };

    public IEnumerable<int> SslPorts
    {
        get {
            return _sslPortsDictionary.Select(pair => pair.Key);
        }
    }

    public String GetPortDescription(int port)
    {
        String desc = _sslPortsDictionary[port];
        if (desc != null) {
            return desc;
        }

        throw new Exception("Unrecognized SSL port");
    } 
}
