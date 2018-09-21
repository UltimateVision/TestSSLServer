using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

class TestSSLServer
{

    static void Usage()
    {
        Console.WriteLine(
"Usage: TestSSLServer [ options ] servername [ port ]");
        Console.WriteLine(
"Options:");
        Console.WriteLine(
"  -h                print this help");
        Console.WriteLine(
"  -v                verbose operation");
        Console.WriteLine(
"  -all              exhaustive cipher suite enumeration");
        Console.WriteLine(
"  -min version      set minimum version (SSLv3, TLSv1, TLSv1.1...)");
        Console.WriteLine(
"  -max version      set maximum version (SSLv3, TLSv1, TLSv1.1...)");
        Console.WriteLine(
"  -sni name         override the SNI contents (use '-' as name to disable)");
        Console.WriteLine(
"  -certs            include full certificates in output");
        Console.WriteLine(
"  -prox name:port   connect through HTTP proxy");
        Console.WriteLine(
"  -proxssl          use SSL/TLS to connect to proxy");
        Console.WriteLine(
"  -ec               add a 'supported curves' extension for all connections");
        Console.WriteLine(
"  -text fname       write text report in file 'fname' ('-' = stdout)");
        Console.WriteLine(
"  -json fname       write JSON report in file 'fname' ('-' = stdout)");
        Environment.Exit(1);
    }

    static void Main(string[] args)
    {
        try
        {
            Process(args);
        }
        catch (Exception e)
        {
            Console.WriteLine(e.ToString());
            Environment.Exit(1);
        }
    }

    private static List<Task> tasks = new List<Task>();
//    private static SSLTestArgs _testArgs = new SSLTestArgs(new List<string>());

    static void Process(string[] args)
    {
        FullTest ft = new FullTest();
        SSLTestArgs _testArgs = new SSLTestArgs(new List<string>());

        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            switch (a.ToLowerInvariant())
            {
                case "-h":
                case "-help":
                case "--help":
                    Usage();
                    break;
                case "-v":
                case "--verbose":
                    ft.Verbose = true;
                    break;
                case "-sni":
                case "--sni":
                    if (++i >= args.Length)
                    {
                        Usage();
                    }
                    ft.ExplicitSNI = args[i];
                    break;
                case "-all":
                case "--all-suites":
                    ft.AllSuites = true;
                    break;
                case "-min":
                case "--min-version":
                    if (++i >= args.Length)
                    {
                        Usage();
                    }
                    ft.MinVersion = ParseVersion(args[i]);
                    if (ft.MinVersion < M.SSLv20
                        || ft.MinVersion > M.TLSv12)
                    {
                        Usage();
                    }
                    break;
                case "-max":
                case "--max-version":
                    if (++i >= args.Length)
                    {
                        Usage();
                    }
                    ft.MaxVersion = ParseVersion(args[i]);
                    if (ft.MaxVersion < M.SSLv20
                        || ft.MaxVersion > M.TLSv12)
                    {
                        Usage();
                    }
                    break;
                case "-certs":
                case "--with-certificates":
                    _testArgs.WithCerts = true;
                    break;
                case "-prox":
                case "--proxy":
                    if (++i >= args.Length)
                    {
                        Usage();
                    }
                    _testArgs.ProxString = args[i];
                    break;
                case "-proxssl":
                case "--proxy-ssl":
                    ft.ProxSSL = true;
                    break;
                case "-ec":
                case "--with-ec-ext":
                    ft.AddECExt = true;
                    break;
                case "-text":
                case "--text-output":
                    if (++i >= args.Length)
                    {
                        Usage();
                    }
                    _testArgs.TextOut = args[i];
                    break;
                case "-json":
                case "--json-output":
                    if (++i >= args.Length)
                    {
                        Usage();
                    }
                    _testArgs.JsonOut = args[i];
                    break;
                case "-ar":
                case "--address-range":
                    _testArgs.MultiAddr = true;
                    break;
                case "-ap":
                case "--all-ports":
                    _testArgs.IterateOverAllSslPorts = true;
                    break;
                default:
                    if (a.Length > 0 && a[0] == '-')
                    {
                        Usage();
                    }
                    _testArgs.R.Add(a);
                    break;
            }
        }
        args = _testArgs.R.ToArray();
        if (args.Length == 0 || args.Length > 2)
        {
            Usage();
        }

        string serverName = args[0];
        int port = -1;
        if (args.Length == 2)
        {
            try
            {
                port = Int32.Parse(args[1]);
            }
            catch (Exception)
            {
                Usage();
            }
        }

        ReportAggregator aggregator = new ReportAggregator();
        aggregator.SetSubnet(serverName);

        if (!_testArgs.MultiAddr) {
            Report.UpdateReportAggregator(aggregator, Run(ft, serverName, port, _testArgs));
        } else {
            IpRange range = new IpRange(serverName);
            IpRangeEnumerator enumerator = new IpRangeEnumerator();
            SslPortEnumerator portEnumerator = new SslPortEnumerator();
            Console.WriteLine("Starting test...");

            Directory.CreateDirectory("raw_results");
            foreach (var address in enumerator.GetIPRange(range)) {
                RunTask(ft, address, 443, aggregator, _testArgs);
            }
            ZipFile.CreateFromDirectory("raw_results", "raw_results_" + serverName.Replace("/","_") + ".zip");
            Directory.Delete("raw_results", true);
        }

        aggregator.SaveCsv();
        aggregator.SaveCerts();
    }

    private static void RunTask(FullTest ft, string address, int sslPort, ReportAggregator aggregator, SSLTestArgs args)
    {
        try {
            Report rp = Run(ft, address, sslPort, args, @"raw_results\", "_" + address + "_" + sslPort);
            Report.UpdateReportAggregator(aggregator, rp);
            aggregator.IncrementScanCounter();
            Console.WriteLine("Done testing {0}:{1}\n", address, sslPort);
        } catch (Exception e) {
            Console.WriteLine("Failed to test {0}:{1} due to {2}", address, sslPort, e.Message);
        }
    }

    static Report Run(FullTest ft, String serverName, Int32 port, SSLTestArgs args, String prefix = "", String suffix = "")
    {
        ft.ServerName = serverName;
        if (port > 0) {
            ft.ServerPort = port;
        }
        if (args.ProxString != null)
        {
            int j = args.ProxString.IndexOf(':');
            if (j > 0)
            {
                try
                {
                    string sp = args.ProxString
                        .Substring(j + 1).Trim();
                    ft.ProxPort = Int32.Parse(sp);
                }
                catch (Exception)
                {
                    Usage();
                }
                ft.ProxName = args.ProxString.Substring(0, j).Trim();
            }
        }

        /*
         * If there is no specified output, then use stdout.
         */
        if (args.TextOut == null && args.JsonOut == null)
        {
            args.TextOut = "-";
        }

        Task<Report> rTask = Task<Report>.Factory.StartNew(ft.Run);
        Thread.Sleep(15000);
        if (!rTask.IsCompleted) {
            throw new Exception("Timeout");
        }

        Report rp = rTask.Result;
//        Report rp = ft.Run();
        rp.ShowCertPEM = args.WithCerts;

        if (args.TextOut != null)
        {
            if (args.TextOut == "-")
            {
                rp.Print(Console.Out);
            }
            else {
                using (TextWriter w =
                    File.CreateText(prefix + args.TextOut + suffix))
                {
                    rp.Print(w);
                }
            }
        }
        if (args.JsonOut != null)
        {
            if (args.JsonOut == "-")
            {
                rp.Print(new JSON(Console.Out));
            }
            else {
                using (TextWriter w =
                    File.CreateText(args.JsonOut + suffix))
                {
                    rp.Print(new JSON(w));
                }
            }
        }

        return rp;
    }

    static int ParseVersion(string vs)
    {
        vs = vs.Trim().ToLowerInvariant();
        if (vs.StartsWith("0x"))
        {
            vs = vs.Substring(2);
            if (vs.Length == 0)
            {
                return -1;
            }
            int acc = 0;
            foreach (char c in vs)
            {
                int d;
                if (c >= '0' && c <= '9')
                {
                    d = c - '0';
                }
                else if (c >= 'a' && c <= 'f')
                {
                    d = c - ('a' - 10);
                }
                else {
                    return -1;
                }
                if (acc > 0xFFF)
                {
                    return -1;
                }
                acc = (acc << 4) + d;
            }
            return acc;
        }

        if (vs.StartsWith("ssl"))
        {
            vs = vs.Substring(3).Trim();
            if (vs.StartsWith("v"))
            {
                vs = vs.Substring(1).Trim();
            }
            switch (vs)
            {
                case "3":
                case "30":
                case "3.0":
                    return M.SSLv30;
                default:
                    return -1;
            }
        }
        else if (vs.StartsWith("tls"))
        {
            vs = vs.Substring(3).Trim();
            if (vs.StartsWith("v"))
            {
                vs = vs.Substring(1).Trim();
            }
            int j = vs.IndexOf('.');
            string suff;
            if (j >= 0)
            {
                suff = vs.Substring(j + 1).Trim();
                vs = vs.Substring(0, j).Trim();
            }
            else {
                suff = "0";
            }
            int maj, min;
            if (!Int32.TryParse(vs, out maj)
                || !Int32.TryParse(suff, out min))
            {
                return -1;
            }
            /*
			 * TLS 1.x is SSL 3.y with y == x+1.
			 * We suppose that TLS 2.x will be encoded
			 * as SSL 4.x, without the +1 thing.
			 */
            if (maj == 1)
            {
                min++;
            }
            if (maj < 1 || maj > 253 || min < 0 || min > 255
                || (maj == 1 && min > 254))
            {
                return -1;
            }
            return ((maj + 2) << 8) + min;
        }
        return -1;
    }
}
