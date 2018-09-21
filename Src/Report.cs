using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

/*
 * This class accumulates the information about the tested server,
 * and produces the report.
 */

class Report {

	/*
	 * Connection name (server name).
	 */
	internal string ConnName {
		get {
			return connName;
		}
		set {
			connName = value;
		}
	}

	/*
	 * Connection port.
	 */
	internal int ConnPort {
		get {
			return connPort;
		}
		set {
			connPort = value;
		}
	}

	/*
	 * Server name sent in the SNI extension. This may be null if
	 * no SNI extension was sent.
	 */
	internal string SNI {
		get {
			return sni;
		}
		set {
			sni = value;
		}
	}

	/*
	 * List of supported SSLv2 cipher suites, in the order returned
	 * by the server (which is purely advisory, since selection is
	 * done by the client). It is null if SSLv2 is not supported.
	 */
	internal int[] SSLv2CipherSuites {
		get {
			return ssl2Suites;
		}
		set {
			ssl2Suites = value;
		}
	}

	/*
	 * Certificate sent by the server if SSLv2 is supported (null
	 * otherwise). It is reported as a chain of length 1.
	 */
	internal X509Chain SSLv2Chain {
		get {
			return ssl2Chain;
		}
	}

	/*
	 * List of supported cipher suites, indexed by protocol version.
	 * This map contains information for version SSL 3.0 and more.
	 */
	internal IDictionary<int, SupportedCipherSuites> CipherSuites {
		get {
			return suites;
		}
	}

	/*
	 * Set to true if we had to shorten our ClientHello messages
	 * (this indicates a server with a fixed, small buffer for
	 * incoming ClientHello).
	 */
	internal bool NeedsShortHello {
		get {
			return shortHello;
		}
		set {
			shortHello = value;
		}
	}

	/*
	 * Set to true if we had to suppress extensions from our
	 * ClientHello (flawed server that does not support extensions).
	 */
	internal bool NoExtensions {
		get {
			return noExts;
		}
		set {
			noExts = value;
		}
	}

	/*
	 * Set to true if the server, at some point, agreed to use
	 * Deflate compression.
	 */
	internal bool DeflateCompress {
		get {
			return compress;
		}
		set {
			compress = value;
		}
	}

	/*
	 * Set to true if the server appears to support secure
	 * renegotiation (at least, it understands and returns an empty
	 * extension; this does not demonstrate that the server would
	 * accept an actual renegotiation, but if it does, then chances
	 * are that it will tag it with the proper extension value).
	 */
	internal bool SupportsSecureRenegotiation {
		get {
			return doesRenego;
		}
		set {
			doesRenego = value;
		}
	}

	/*
	 * Set the server time offset (serverTime - clientTime), in
	 * milliseconds.
	 *
	 * Int64.MinValue means that the server sends 0 (the standard
	 * method to indicate that the clock is not available).
	 *
	 * Int64.MaxValue means that the server sends random bytes
	 * in the time field (non-standard, but widespread because
	 * OpenSSL does that by default since September 2013).
	 */
	internal long ServerTimeOffset {
		get {
			return serverTimeOffset;
		}
		set {
			serverTimeOffset = value;
		}
	}

	/*
	 * Minimal size (in bits) of DH parameters sent by server. If
	 * server never used DHE or SRP, then this is 0.
	 */
	internal int MinDHSize {
		get {
			return minDHSize;
		}
		set {
			minDHSize = value;
		}
	}

	/*
	 * Minimal size (in bits) of ECDH parameters sent by server. If
	 * server never used ECDHE, then this is 0. This value is for
	 * handshakes where the client DID NOT send a "supported curve"
	 * extension.
	 */
	internal int MinECSize {
		get {
			return minECSize;
		}
		set {
			minECSize = value;
		}
	}

	/*
	 * Minimal size (in bits) of ECDH parameters sent by server. If
	 * server never used ECDHE, then this is 0. This value is for
	 * handshakes where the client sent a "supported curve" extension.
	 */
	internal int MinECSizeExt {
		get {
			return minECSizeExt;
		}
		set {
			minECSizeExt = value;
		}
	}

	/*
	 * Named curves used by the server for ECDH parameters.
	 */
	internal SSLCurve[] NamedCurves {
		get {
			return namedCurves;
		}
		set {
			namedCurves = value;
		}
	}

	/*
	 * Named curves spontaneously used by the server for ECDH
	 * parameters. These are the curves that the server elected to
	 * use in the absence of a "supported elliptic curves" extension
	 * from the client.
	 */
	internal SSLCurve[] SpontaneousNamedCurves {
		get {
			return spontaneousNamedCurves;
		}
		set {
			spontaneousNamedCurves = value;
		}
	}

	/*
	 * If non-zero, then this is the size of the "explicit prime"
	 * curve selected by the server.
	 */
	internal int CurveExplicitPrime {
		get {
			return curveExplicitPrime;
		}
		set {
			curveExplicitPrime = value;
		}
	}

	/*
	 * If non-zero, then this is the size of the "explicit char2"
	 * curve selected by the server.
	 */
	internal int CurveExplicitChar2 {
		get {
			return curveExplicitChar2;
		}
		set {
			curveExplicitChar2 = value;
		}
	}

	/*
	 * Set to true if one ServerKeyExchange message (at least) could
	 * not be fully decoded.
	 */
	internal bool UnknownSKE {
		get {
			return unknownSKE;
		}
		set {
			unknownSKE = value;
		}
	}

	/*
	 * Get all certificate chains gathered so far.
	 */
	internal X509Chain[] AllChains {
		get {
			return M.ToValueArray(chains);
		}
	}

	/*
	 * The warnings aggregated after analysis. The map is indexed
	 * by warning identifier; map values are explicit messsages.
	 */
	internal IDictionary<string, string> Warnings {
		get {
			return warnings;
		}
	}

	/*
	 * If true, then the report will include the whole certificates
	 * sent by the server (PEM format).
	 */
	internal bool ShowCertPEM {
		get {
			return withPEM;
		}
		set {
			withPEM = value;
		}
	}

	string connName;
	int connPort;
	string sni;
	int[] ssl2Suites;
	X509Chain ssl2Chain;
	bool shortHello;
	bool noExts;
	IDictionary<int, SupportedCipherSuites> suites;
	IDictionary<string, X509Chain> chains;
	bool compress;
	long serverTimeOffset;
	bool doesRenego;
	int minDHSize;
	int minECSize;
	int minECSizeExt;
	SSLCurve[] namedCurves;
	SSLCurve[] spontaneousNamedCurves;
	int curveExplicitPrime;
	int curveExplicitChar2;
	bool unknownSKE;

	IDictionary<string, string> warnings;
	bool withPEM;

	/*
	 * Create an empty report instance.
	 */
	internal Report()
	{
		suites = new SortedDictionary<int, SupportedCipherSuites>();
		chains = new SortedDictionary<string, X509Chain>(
			StringComparer.Ordinal);
		serverTimeOffset = Int64.MinValue;
	}

	/*
	 * Set the cipher suites supported for a specific protocol version
	 * (SSLv3+).
	 */
	internal void SetCipherSuites(int version, SupportedCipherSuites scs)
	{
		suites[version] = scs;
	}

	/*
	 * Record a certificate sent by a SSLv2 server. The certificate
	 * is alone.
	 */
	internal void SetSSLv2Certificate(byte[] ssl2Cert)
	{
		if (ssl2Cert == null) {
			ssl2Chain = null;
		} else {
			ssl2Chain = X509Chain.Make(
				new byte[][] { ssl2Cert }, true);
		}
	}

	/*
	 * Record a new certificate chain sent by the server. Duplicates
	 * are merged.
	 */
	internal void AddServerChain(byte[][] chain)
	{
		X509Chain xc = X509Chain.Make(chain, true);
		chains[xc.Hash] = xc;
	}

	/*
	 * Test whether a given named curve is part of the "spontaneous"
	 * named curves.
	 */
	bool IsSpontaneous(SSLCurve sc)
	{
		if (spontaneousNamedCurves == null) {
			return false;
		}
		for (int i = 0; i < spontaneousNamedCurves.Length; i ++) {
			if (sc.Id == spontaneousNamedCurves[i].Id) {
				return true;
			}
		}
		return false;
	}

	/*
	 * Analyse data and compute the list of relevant warnings.
	 */
	internal void Analyse()
	{
		warnings = new SortedDictionary<string, string>(
			StringComparer.Ordinal);
		if (ssl2Suites != null && ssl2Suites.Length > 0) {
			warnings["PV002"] = "Server supports SSL 2.0.";
		}
		if (suites.ContainsKey(M.SSLv30)) {
			warnings["PV003"] = "Server supports SSL 3.0.";
		}
		if (unknownSKE) {
			warnings["SK001"] = "Some Server Key Exchange messages"
				+ " could not be processed.";
		}
		if (minDHSize > 0 && minDHSize < 2048) {
			warnings["SK002"] = "Server uses DH parameters smaller"
				+ " than 2048 bits.";
		}
		if (minECSize > 0 && minECSize < 192) {
			warnings["SK003"] = "Server chooses ECDH parameters"
				+ " smaller than 192 bits.";
		}
		if (minECSizeExt > 0 && minECSizeExt < 192) {
			warnings["SK004"] = "Server supports ECDH parameters"
				+ " smaller than 192 bits (if requested).";
		}
		if (NeedsShortHello) {
			warnings["PV001"] = "Server needs short ClientHello.";
		}
		if (NoExtensions) {
			warnings["PV004"] =
				"Server does not tolerate extensions.";
		}
		if (DeflateCompress) {
			warnings["CP001"] = "Server supports compression.";
		}

		bool hasCS0 = false;
		bool hasCS1 = false;
		bool hasCS2 = false;
		bool hasCSX = false;
		bool hasRC4 = false;
		bool hasNoFS = false;
		foreach (int pv in suites.Keys) {
			SupportedCipherSuites scs = suites[pv];
			foreach (int s in scs.Suites) {
				CipherSuite cs;
				if (CipherSuite.ALL.TryGetValue(s, out cs)) {
					switch (cs.Strength) {
					case 0: hasCS0 = true; break;
					case 1: hasCS1 = true; break;
					case 2: hasCS2 = true; break;
					}
					if (cs.IsRC4) {
						hasRC4 = true;
					}
					if (!cs.HasForwardSecrecy) {
						hasNoFS = true;
					}
				} else {
					hasCSX = true;
				}
			}
		}
		if (hasCS0) {
			warnings["CS001"] =
				"Server supports unencrypted cipher suites.";
		}
		if (hasCS1) {
			warnings["CS002"] = "Server supports very weak"
				+ " cipher suites (40 bits).";
		}
		if (hasCS2) {
			warnings["CS003"] = "Server supports weak"
				+ " cipher suites (56 bits).";
		}
		if (hasCSX) {
			warnings["CS004"] = "Server supports unrecognized"
				+ " cipher suites (unknown strength).";
		}
		if (hasRC4) {
			warnings["CS005"] = "Server supports RC4.";
		}
		if (hasNoFS) {
			warnings["CS006"] = "Server supports cipher suites"
				+ " with no forward secrecy.";
		}
		if (!doesRenego) {
			warnings["RN001"] = "Server does not support"
				+ " secure renegotiation.";
		}
	}

	/*
	 * Print the report on the provided writer (text version for
	 * humans).
	 */
	internal void Print(TextWriter w)
	{
		w.WriteLine("Connection: {0}:{1}", connName, connPort);
		if (sni == null) {
			w.WriteLine("No SNI sent");
		} else {
			w.WriteLine("SNI: {0}", sni);
		}
		if (ssl2Suites != null && ssl2Suites.Length > 0) {
			w.WriteLine("  {0}", M.VersionString(M.SSLv20));
			foreach (int s in ssl2Suites) {
				w.WriteLine("     {0}",
					CipherSuite.ToNameV2(s));
			}
		}
		SupportedCipherSuites last = null;
		foreach (int v in suites.Keys) {
			w.Write("  {0}:", M.VersionString(v));
			SupportedCipherSuites scs = suites[v];
			if (scs.Equals(last)) {
				w.WriteLine(" idem");
				continue;
			}
			last = scs;
			w.WriteLine();
			w.Write("     server selection: ");
			if (scs.PrefClient) {
				w.WriteLine("uses client preferences");
			} else if (scs.PrefServer) {
				w.WriteLine("enforce server preferences");
			} else {
				w.WriteLine("complex");
			}
			foreach (int s in scs.Suites) {
				CipherSuite cs;
				string strength;
				string fsf;
				string anon;
				string kt;
				if (CipherSuite.ALL.TryGetValue(s, out cs)) {
					strength = cs.Strength.ToString();
					fsf = cs.HasForwardSecrecy ? "f" : "-";
					anon = cs.IsAnonymous ? "A" : "-";
					kt = cs.ServerKeyType;
				} else {
					strength = "?";
					fsf = "?";
					anon = "?";
					kt = "?";
				}
				w.WriteLine("     {0}{1}{2} (key: {3,4})  {4}",
					strength, fsf, anon, kt,
					CipherSuite.ToName(s));
			}
		}
		w.WriteLine("=========================================");
		if (ssl2Chain != null) {
			w.WriteLine("+++++ SSLv2 certificate");
			PrintCert(w, ssl2Chain, 0, withPEM);
		}
		w.WriteLine("+++++ SSLv3/TLS: {0} certificate chain(s)",
			chains.Count);
		foreach (X509Chain xchain in chains.Values) {
			PrintChain(w, xchain, withPEM);
		}
		w.WriteLine("=========================================");
		w.WriteLine("Server compression support: {0}",
			DeflateCompress ? "yes" : "no");
		if (serverTimeOffset == Int64.MinValue) {
			w.WriteLine("Server does not send its system time.");
		} else if (serverTimeOffset == Int64.MaxValue) {
			w.WriteLine("Server sends a random system time.");
		} else {
			DateTime dt = DateTime.UtcNow;
			dt = dt.AddMilliseconds((double)serverTimeOffset);
			w.WriteLine("Server time: {0:yyyy-MM-dd HH:mm:ss} UTC"
				+ " (offset: {1} ms)", dt, serverTimeOffset);
		}
		w.WriteLine("Secure renegotiation support: {0}",
			doesRenego ? "yes" : "no");
		if (minDHSize > 0) {
			w.WriteLine("Minimum DH size: {0}", minDHSize);
		}
		if (minECSize > 0) {
			w.WriteLine("Minimum EC size (no extension):   {0}",
				minECSize);
		}
		if (minECSizeExt > 0) {
			w.WriteLine("Minimum EC size (with extension): {0}",
				minECSizeExt);
		}
		if (namedCurves != null && namedCurves.Length > 0) {
			w.WriteLine("Supported curves (size and name)"
				+ " ('*' = selected by server):");
			foreach (SSLCurve nc in namedCurves) {
				w.WriteLine("  {0} {1,3}  {2}",
					IsSpontaneous(nc) ? "*" : " ",
					nc.Size, nc.Name);
			}
			if (curveExplicitPrime > 0) {
				w.WriteLine("  explicit prime, size = {0}",
					curveExplicitPrime);
			}
			if (curveExplicitChar2 > 0) {
				w.WriteLine("  explicit char2, size = {0}",
					curveExplicitChar2);
			}
		}

		w.WriteLine("=========================================");
		if (warnings == null) {
			Analyse();
		}
		if (warnings.Count == 0) {
			w.WriteLine("No warning.");
		} else {
			foreach (string k in warnings.Keys) {
				w.WriteLine("WARN[{0}]: {1}", k, warnings[k]);
			}
		}
	}

    public static void PrintChain(TextWriter w, X509Chain xchain, bool withPEM)
    {
        int n = xchain.Elements.Length;
        w.WriteLine("+++ chain: length={0}", n);
        if (xchain.Decodable) {
            w.WriteLine("names match:        {0}",
                xchain.NamesMatch ? "yes" : "no");
            w.WriteLine("includes root:      {0}",
                xchain.IncludesRoot ? "yes" : "no");
            w.Write("signature hash(es):");
            foreach (string name in xchain.SignHashes) {
                w.Write(" {0}", name);
            }
            w.WriteLine();
        } else if (n == 0) {
            w.WriteLine("CHAIN IS EMPTY");
        } else {
            w.WriteLine("CHAIN PROCESSING ERROR");
        }
        for (int i = 0; i < n; i ++) {
            w.WriteLine("+ certificate order: {0}", i);
            PrintCert(w, xchain, i, withPEM);
        }
    }

    public static void PrintCert(TextWriter w, X509Chain xchain, int num, bool withPEM)
	{
		w.WriteLine("thumprint:  {0}", xchain.ThumbprintsRev[num]);
		X509Cert xc = xchain.ElementsRev[num];
		if (xc == null) {
			w.WriteLine("UNDECODABLE: {0}",
				xchain.DecodingIssuesRev[num]);
		} else {
			w.WriteLine("serial:     {0}", xc.SerialHex);
			w.WriteLine("subject:    {0}", xc.Subject.ToString());
			w.WriteLine("issuer:     {0}", xc.Issuer.ToString());
			w.WriteLine("valid from: {0:yyyy-MM-dd HH:mm:ss} UTC",
				xc.ValidFrom);
			w.WriteLine("valid to:   {0:yyyy-MM-dd HH:mm:ss} UTC",
				xc.ValidTo);
			w.WriteLine("key type:   {0}", xc.KeyType);
			w.WriteLine("key size:   {0}", xc.KeySize);
			string cname = xc.CurveName;
			if (cname != null) {
				w.WriteLine("key curve:  {0}", cname);
			}
			w.WriteLine("sign hash:  {0}", xc.HashAlgorithm);
			if (xc.SelfIssued) {
				w.WriteLine("(self-issued)");
			}
			if (num == 0) {
				w.Write("server names:");
				string[] names = xc.ServerNames;
				if (names.Length == 0) {
					w.WriteLine(" NONE");
				} else {
					w.WriteLine();
					foreach (string name in names) {
						w.WriteLine("   {0}", name);
					}
				}
			}
		}
		if (withPEM) {
		    if (xchain.EncodedRev[num] != null) {
		        M.WritePEM(w, "CERTIFICATE", xchain.EncodedRev[num]);
		    }
		}
	}

	/*
	 * Encode the report as JSON.
	 */
	internal void Print(JSON js)
	{
		js.OpenInit(false);
		js.AddPair("connectionName", connName);
		js.AddPair("connectionPort", connPort);
		js.AddPair("SNI", sni);
		if (ssl2Suites != null && ssl2Suites.Length > 0) {
			js.OpenPairObject("SSLv2");
			js.OpenPairArray("suites");
			foreach (int s in ssl2Suites) {
				js.OpenElementObject();
				js.AddPair("id", s);
				js.AddPair("name", CipherSuite.ToNameV2(s));
				js.Close();
			}
			js.Close();
			js.Close();
		}

		foreach (int v in suites.Keys) {
			js.OpenPairObject(M.VersionString(v));
			SupportedCipherSuites scs = suites[v];
			string sel;
			if (scs.PrefClient) {
				sel = "client";
			} else if (scs.PrefServer) {
				sel = "server";
			} else {
				sel = "complex";
			}
			js.AddPair("suiteSelection", sel);
			js.OpenPairArray("suites");
			foreach (int s in scs.Suites) {
				js.OpenElementObject();
				js.AddPair("id", s);
				js.AddPair("name", CipherSuite.ToName(s));
				CipherSuite cs;
				if (CipherSuite.ALL.TryGetValue(s, out cs)) {
					js.AddPair("strength", cs.Strength);
					js.AddPair("forwardSecrecy",
						cs.HasForwardSecrecy);
					js.AddPair("anonymous",
						cs.IsAnonymous);
					js.AddPair("serverKeyType",
						cs.ServerKeyType);
				}
				js.Close();
			}
			js.Close();
			js.Close();
		}

		if (ssl2Chain != null) {
			js.OpenPairObject("ssl2Cert");
			PrintCert(js, ssl2Chain, 0);
			js.Close();
		}

		js.OpenPairArray("ssl3Chains");
		foreach (X509Chain xchain in chains.Values) {
			js.OpenElementObject();
			int n = xchain.Elements.Length;
			js.AddPair("length", n);
			js.AddPair("decoded", xchain.Decodable);
			if (xchain.Decodable) {
				js.AddPair("namesMatch", xchain.NamesMatch);
				js.AddPair("includesRoot", xchain.IncludesRoot);
				js.OpenPairArray("signHashes");
				foreach (string name in xchain.SignHashes) {
					js.AddElement(name);
				}
				js.Close();
			}
			js.OpenPairArray("certificates");
			for (int i = 0; i < n; i ++) {
				js.OpenElementObject();
				PrintCert(js, xchain, i);
				js.Close();
			}
			js.Close();
			js.Close();
		}
		js.Close();

		js.AddPair("deflateCompress", DeflateCompress);
		if (serverTimeOffset == Int64.MinValue) {
			js.AddPair("serverTime", "none");
		} else if (serverTimeOffset == Int64.MaxValue) {
			js.AddPair("serverTime", "random");
		} else {
			DateTime dt = DateTime.UtcNow;
			dt = dt.AddMilliseconds((double)serverTimeOffset);
			js.AddPair("serverTime", string.Format(
				"{0:yyyy-MM-dd HH:mm:ss} UTC", dt));
			js.AddPair("serverTimeOffsetMillis",
				serverTimeOffset);
		}
		js.AddPair("secureRenegotiation", doesRenego);
		if (minDHSize > 0) {
			js.AddPair("minDHSize", minDHSize);
		}
		if (minECSize > 0) {
			js.AddPair("minECSize", minECSize);
		}
		if (minECSizeExt > 0) {
			js.AddPair("minECSizeExt", minECSizeExt);
		}

		if ((namedCurves != null && namedCurves.Length > 0)
			|| curveExplicitPrime > 0 || curveExplicitChar2 > 0)
		{
			js.OpenPairArray("namedCurves");
			foreach (SSLCurve nc in namedCurves) {
				js.OpenElementObject();
				js.AddPair("name", nc.Name);
				js.AddPair("size", nc.Size);
				js.AddPair("spontaneous", IsSpontaneous(nc));
				js.Close();
			}
			if (curveExplicitPrime > 0) {
				js.OpenElementObject();
				js.AddPair("name", "explicitPrime");
				js.AddPair("size", curveExplicitPrime);
				js.Close();
			}
			if (curveExplicitChar2 > 0) {
				js.OpenElementObject();
				js.AddPair("name", "explicitChar2");
				js.AddPair("size", curveExplicitChar2);
				js.Close();
			}
			js.Close();
		}

		if (warnings == null) {
			Analyse();
		}
		js.OpenPairArray("warnings");
		foreach (string k in warnings.Keys) {
			js.OpenElementObject();
			js.AddPair("id", k);
			js.AddPair("text", warnings[k]);
			js.Close();
		}
		js.Close();
		js.Close();
	}

	/*
	 * Add certificate to output. The caller is responsible for
	 * opening the certificate object.
	 */
	void PrintCert(JSON js, X509Chain xchain, int num)
	{
		js.AddPair("thumbprint", xchain.ThumbprintsRev[num]);
		X509Cert xc = xchain.ElementsRev[num];
		js.AddPair("decodable", xc != null);
		if (xc == null) {
			js.AddPair("decodeError",
				xchain.DecodingIssuesRev[num]);
		} else {
			js.AddPair("serialHex", xc.SerialHex);
			js.AddPair("subject", xc.Subject.ToString());
			js.AddPair("issuer", xc.Issuer.ToString());
			js.AddPair("validFrom", string.Format(
				"{0:yyyy-MM-dd HH:mm:ss} UTC", xc.ValidFrom));
			js.AddPair("validTo", string.Format(
				"{0:yyyy-MM-dd HH:mm:ss} UTC", xc.ValidTo));
			js.AddPair("keyType", xc.KeyType);
			js.AddPair("keySize", xc.KeySize);
			string cname = xc.CurveName;
			if (cname != null) {
				js.AddPair("keyCurve", cname);
			}
			js.AddPair("signHash", xc.HashAlgorithm);
			js.AddPair("selfIssued", xc.SelfIssued);
			if (num == 0) {
				js.OpenPairArray("serverNames");
				foreach (string name in xc.ServerNames) {
					js.AddElement(name);
				}
				js.Close();
			}
		}
		if (withPEM) {
			js.AddPair("PEM",
				M.ToPEM("CERTIFICATE", xchain.EncodedRev[num]));
		}
	}

    public static void UpdateReportAggregator(ReportAggregator aggregator, Report report)
    {
        String serverUnderTest = $"{report.ConnName}:{report.ConnPort}";
        if (report.SSLv2Chain != null) {
            aggregator.AddSsl2Cert(serverUnderTest, report.SSLv2Chain);
            X509Cert xc = report.SSLv2Chain.ElementsRev[0];
            if (xc != null && xc.ValidTo.CompareTo(DateTime.Now) < 0) {
                aggregator.AddOverduedCertificate(serverUnderTest, xc.ValidTo);
            }
        }

        if (report.ssl2Suites != null && report.ssl2Suites.Length > 0)
        {
            aggregator.AddSuportedSslVersion(M.VersionString(M.SSLv20));
            foreach (int s in report.ssl2Suites) {
                aggregator.AddSupportedCipherSuite(CipherSuite.ToNameV2(s));
            }
        }

        aggregator.AddSsl3Certs(serverUnderTest, report.chains.Values);
        InspectCerts(aggregator, report, serverUnderTest);

        foreach (int v in report.suites.Keys)
        {
            aggregator.AddSuportedSslVersion(M.VersionString(v));
            SupportedCipherSuites scs = report.suites[v];
            if (scs.PrefClient) {
                aggregator.AddCipherSuiteSelectionMode("uses client preferences");
            } else if (scs.PrefServer) {
                aggregator.AddCipherSuiteSelectionMode("enforce server preferences");
            } else {
                aggregator.AddCipherSuiteSelectionMode("complex");
            }
            foreach (int s in scs.Suites)
            {
                CipherSuite cs;
                string strength;
                string fsf;
                string anon;
                string kt;
                if (CipherSuite.ALL.TryGetValue(s, out cs))
                {
                    strength = cs.Strength.ToString();
                    fsf = cs.HasForwardSecrecy ? "f" : "-";
                    anon = cs.IsAnonymous ? "A" : "-";
                    kt = cs.ServerKeyType;
                }
                else {
                    strength = "?";
                    fsf = "?";
                    anon = "?";
                    kt = "?";
                }
                aggregator.AddSupportedCipherSuite($"{strength}{fsf}{anon} (key: {kt,4})  {CipherSuite.ToName(s)}");
            }
        }

        foreach (var warning in report.Warnings) {
            aggregator.AddWarning(warning.Value);
        }
    }

    private static void InspectCerts(ReportAggregator aggregator, Report report, string serverUnderTest)
    {
        foreach (var x509Chain in report.chains.Values) {
            int n = x509Chain.Elements.Length;
            for (int i = 0; i < n; i++) {
                X509Cert xc = x509Chain.ElementsRev[0];
                if (xc != null && xc.ValidTo.CompareTo(DateTime.Now) < 0) {
                    aggregator.AddOverduedCertificate(serverUnderTest, xc.ValidTo);
                    return;
                }
            }
        }
    }
}
