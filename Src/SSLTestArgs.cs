using System.Collections.Generic;

public struct SSLTestArgs {
    public List<string> R;
    public bool WithCerts;
    public bool MultiAddr;
    public string ProxString;
    public string TextOut;
    public string JsonOut;
    public bool IterateOverAllSslPorts;

    public SSLTestArgs(List<string> R)
    {
        this.R = R;
        WithCerts = false;
        MultiAddr = false;
        ProxString = null;
        TextOut = null;
        JsonOut = null;
        IterateOverAllSslPorts = false;
    }
}