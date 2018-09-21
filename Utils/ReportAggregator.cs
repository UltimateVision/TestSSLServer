using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

class ReportAggregator
{
    private String subnet;
    private Dictionary<String, int> _supportedSslVersions = new Dictionary<string, int>();
    private Dictionary<String, int> _supportedCipherSuites = new Dictionary<string, int>();
    private Dictionary<String, int> _warnings = new Dictionary<string, int>();
    private Dictionary<String, int> _cipherSuiteSelectionMode = new Dictionary<string, int>();

    private Dictionary<String, ICollection<X509Chain>> _ssl3certList = new Dictionary<string, ICollection<X509Chain>>();
    private Dictionary<String, X509Chain> _ssl2certList = new Dictionary<string, X509Chain>();

    private Dictionary<String, DateTime> _overduedCertList = new Dictionary<string, DateTime>();

    private int _scanCounter = 0;

    private static readonly object _lock = new object();

    public void SetSubnet(String subnet)
    {
        this.subnet = subnet;
    }

    public void AddSuportedSslVersion(String ssl)
    {
        lock (_lock) {
            AddValue(_supportedSslVersions, ssl);
        }
    }

    public void AddSupportedCipherSuite(String cipherSuite)
    {
        lock (_lock) {
            AddValue(_supportedCipherSuites, cipherSuite);
        }
    }

    public void AddWarning(String warning)
    {
        lock (_lock) {
            AddValue(_warnings, warning);
        }
    }

    public void AddCipherSuiteSelectionMode(String mode)
    {
        lock (_lock) {
            AddValue(_cipherSuiteSelectionMode, mode);
        }
    }

    public void AddSsl2Cert(String serverName, X509Chain chain)
    {
        lock (_lock) {
            _ssl2certList[serverName] = chain;
        }
    }

    public void AddSsl3Certs(String serverName, ICollection<X509Chain> certs)
    {
        lock (_lock) {
            _ssl3certList[serverName] = certs;
        }
    }

    public void AddOverduedCertificate(String serverName, DateTime validTo)
    {
        lock (_lock) {
            _overduedCertList[serverName] = validTo;
        }
    }

    public void IncrementScanCounter()
    {
        lock (_lock) {
            _scanCounter++;
        }
    }

    private void AddValue(Dictionary<String, int> dictionary, String key)
    {
        if (dictionary.ContainsKey(key))
        {
            dictionary[key]++;
        }
        else {
            dictionary[key] = 1;
        }
    }

    public void SaveCsv()
    {
        Console.WriteLine("Exporting csv file...");
        try {
            using (StreamWriter sw = new StreamWriter(new FileStream("report_" + subnet.Replace("/", "_") + ".csv", FileMode.Append))) {
                sw.WriteLine("Report for subnet " + subnet);
                sw.Write(FormatAsCsvSection(_supportedSslVersions, "Supported ssl versions"));
                sw.Write(FormatAsCsvSection(_supportedCipherSuites, "Supported Cipher Suites"));
                sw.Write(FormatAsCsvSection(_cipherSuiteSelectionMode, "Cipher suite selection modes"));
                sw.Write(FormatAsCsvSection(_warnings, "Warnings"));
                sw.Write(FormatAsCsvSection(_overduedCertList, "Outdated certs"));
                sw.Write($"Scanned addresses;{_scanCounter}\n");
            }
            Console.WriteLine("Done");
        } catch (Exception e) {
            Console.WriteLine($"Failed due to {e.Message}. Trying to dump json...");
            using (StreamWriter sw = new StreamWriter(new FileStream($"{subnet.Replace("/", "_")}_stat.json", FileMode.Truncate))) {
                sw.Write(JsonConvert.SerializeObject(_supportedSslVersions));
                sw.Write(JsonConvert.SerializeObject(_supportedCipherSuites));
                sw.Write(JsonConvert.SerializeObject(_cipherSuiteSelectionMode));
                sw.Write(JsonConvert.SerializeObject(_warnings));
                sw.Write(JsonConvert.SerializeObject(_overduedCertList));
            }
            Console.WriteLine("Done");
        }
    }

    private String FormatAsCsvSection<T>(Dictionary<String, T> dictionary, String sectionName)
    {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine(sectionName);
        foreach (var kvp in dictionary) {
            sb.AppendLine($"{kvp.Key};{kvp.Value}");
        }
        sb.AppendLine(";");
        return sb.ToString();
    }

    public void SaveCerts()
    {
        Directory.CreateDirectory(@"certs\certs_ssl2");
        Directory.CreateDirectory(@"certs\certs_ssl3_tls");

        foreach (var x509Chain in _ssl2certList) {
            using (StreamWriter sw = new StreamWriter(new FileStream(@"certs\certs_ssl2\" + x509Chain.Key.Replace(":", "_") + "cert", FileMode.Create))) {
                Report.PrintCert(sw, x509Chain.Value, 0, true);
            }
        }

        foreach (var certChains in _ssl3certList) {
            using (StreamWriter sw = new StreamWriter(new FileStream(@"certs\certs_ssl3_tls\" + certChains.Key.Replace(":", "_") + "cert", FileMode.Create))) {
                foreach (X509Chain xchain in certChains.Value) {
                    Report.PrintChain(sw, xchain, true);
                }
            }
        }

        string startPath = @"certs";
        string zipPath = subnet.Replace("/", "_") + "_certs.zip";

        ZipFile.CreateFromDirectory(startPath, zipPath);
        Directory.Delete("certs", true);
    }
}
