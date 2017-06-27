#TRUSTED 60ffb05cf91aa31b4f25682c70efd27c4c08ee7fd17b8ebb945a67b1899776217900edcf03936d19d6b2fd087feb946a601c70989d0f74c80b0e410e85972f557e2badb2b9d4627c5ac0e335f4712d68244f1fed33866cf158866ac447ca3b8f72ceedf88424c629e25fc5523bb3689389a3e3b6c21b3164787f2cd8298ff9debfcbb39a64f93961143d895c3c631048ce51fbb5d030fbeb589d10ca45208c85042ffc32db8e80dcd0a1017f91a163aee90168d1cb410568d58e367c2a1a6cfe78d540c5a14ea834c6e8f9cffe677d0f83d1d932421658c39711aebecb95e96f1697a415e54ae59ff299904b6f7b198aef159da69751378004d5f4353c25001eea239aeb23a5d8a6b6a1a9703c68c69374f9d888d353d6f8faa942f12e587278a26ec975fa67d0be9edede258f5c584abc0c016b596be3c6e2f774e6407859539e186d3207b18082db5f19a0a7af6b67eb8da4664f63a597a428d654567cb4d2df059a2f2fe85e44bfa6aba9b414fff3645dd70439715f71f7e290d0cabdaf53515599104d9823e6487de306e82fc2de691f8b1cd2dbbcd0fb38665a073b4b46dc195496942d2e3f914553c1d57a60e2e7c499ec0829c094c9dfcab918c60a3a353614403eb5962bb981823e5f94aa82616522748121d03880a925f9616b670b06028c9e8dd962c990699bcc9045262c67564bb419b471426fbcce5a6d6ce9f8
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a0080b95d57.shtml

include("compat.inc");

if (description)
{
 script_id(56321);
 script_version("1.15");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/12");

 script_cve_id("CVE-2011-3273", "CVE-2011-3281");
 script_bugtraq_id(49826);
 script_osvdb_id(75927, 75928);
 script_xref(name:"CISCO-BUG-ID", value:"CSCti79848");
 script_xref(name:"CISCO-BUG-ID", value:"CSCto68554");
 script_xref(name:"CISCO-BUG-ID", value:"CSCtq28732");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20110928-zbfw");

 script_name(english:"Cisco IOS Software IPS and Zone-Based Firewall Vulnerabilities - Cisco Systems");
 script_summary(english:"Checks the IOS version.");

 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
"Cisco IOS Software contains two vulnerabilities related to Cisco IOS
Intrusion Prevention System (IPS) and Cisco IOS Zone-Based Firewall
features. These vulnerabilities are :

  - Memory leak

  - Denial of service caused by processing specially
    crafted HTTP packets

Cisco has released free software updates that address these
vulnerabilities. Workarounds that mitigate these vulnerabilities are
not available.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e333cc98");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a0080b95d57.shtml
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?26586489");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20110928-zbfw.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/29");
 script_set_attribute(attribute:"patch_publication_date", value:"2011/09/29");
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/29");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2011-2014 Tenable Network Security, Inc.");
 script_family(english:"CISCO");

 script_dependencies("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");

 exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (version == '15.1(4)XB4') flag++;
else if (version == '15.1(1)XB') flag++;
else if (version == '15.1(3)T1') flag++;
else if (version == '15.1(3)T') flag++;
else if (version == '15.1(2)T3') flag++;
else if (version == '15.1(2)T2a') flag++;
else if (version == '15.1(2)T2') flag++;
else if (version == '15.1(2)T1') flag++;
else if (version == '15.1(2)T0a') flag++;
else if (version == '15.1(2)T') flag++;
else if (version == '15.1(1)T3') flag++;
else if (version == '15.1(1)T2') flag++;
else if (version == '15.1(1)T1') flag++;
else if (version == '15.1(1)T') flag++;
else if (version == '15.1(4)M0b') flag++;
else if (version == '15.1(4)M0a') flag++;
else if (version == '15.1(4)M') flag++;
else if (version == '15.1(2)GC1') flag++;
else if (version == '15.1(2)GC') flag++;
else if (version == '15.0(1)XA5') flag++;
else if (version == '15.0(1)XA4') flag++;
else if (version == '15.0(1)XA3') flag++;
else if (version == '15.0(1)XA2') flag++;
else if (version == '15.0(1)XA1') flag++;
else if (version == '15.0(1)XA') flag++;
else if (version == '15.0(1)M6') flag++;
else if (version == '15.0(1)M5') flag++;
else if (version == '15.0(1)M4') flag++;
else if (version == '15.0(1)M3') flag++;
else if (version == '15.0(1)M2') flag++;
else if (version == '15.0(1)M1') flag++;
else if (version == '15.0(1)M') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_ips_interfaces", "show ip ips interfaces");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"IPS rule", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }

    buf = cisco_command_kb_item("Host/Cisco/Config/show_zone_security", "show zone security");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"Member Interfaces:", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
