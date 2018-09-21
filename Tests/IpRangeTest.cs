using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using NUnit.Framework.Internal;
using NUnit.Framework;

namespace TestSslServer.Tests
{
    [TestFixture]
    class IpRangeTest
    {
        [Test]
        public void TestIpRange()
        {
            IpRange range = new IpRange("148.81.0.0/16");
            Assert.That(range.GetFrom().ToString(), Is.EqualTo("148.81.0.0"));
            Assert.That(range.GetTo().ToString(), Is.EqualTo("148.81.255.255"));
        }
    }
}
