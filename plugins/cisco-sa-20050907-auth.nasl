#TRUSTED 00470abefe38734e5da7d72b6a98e9d6bf27eb5cccc8b21aa8f6d4bf5d8a54b1c96be81c0e6ce26034280880d92c8df48569523d321b63ef63a4df49a66b9e576f8a5fbf8c329284c9fd4b82dcf0425d7c5f85c9d7d87882124c6d4604ccb94b6496aa9befc6388b7a8464e316e1e5844b669a0deff757b04973c3c2de15fc066bacdc4de9ca5b60d8a26a90f211758b4bd4b952bc423585fdeb3a9ee2f4766624965ba5d232bbaaea55703f80b57055eade6de8d2392316b5575ff1b60c7843731f1f5493f12b1c82d9b003de8dda4ca3b46635a521a41b0bfb47807f205874ae20f8ec012d0a976b091aa74e559688ffec864fa549bc681ba3733577703f6ac6ffb7c3881972f4a2e25d254fcb05476b79bdaab1d6e0c19235715e8bb7cf3bd4817060253607cdbdfcc6755a5a095ceaefd3ccf92d54a732b4dbfceca84277b5da433e31e358eeacd6ae8436ed270d064fbff7f5e420eaaed3382cd32b24ee1c6d90c040cac061ef24d2b717920e36ff77196c5c80e4f3d89026ec9dcbf3c7068bc94e65886c260673dc8739bf594397b1e2d3596b886234266f1c03f9c83ee26e425f7e8e5ab25a5965d578ef13c47b56709c1e113a13d4eba6e4ef9cfc499589fc1d2083f1652a2aa9ac2051e08443927e834e521b67de49bd16ad953587544a796a9ba6e8230b9e0c184b3dd0bd8944ce50cd78995b595c3334b15cc3f2
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a00805117cb.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48988);
 script_version("1.14");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");
 script_cve_id("CVE-2005-2841");
 script_bugtraq_id(14770);
 script_osvdb_id(19227);
 script_xref(name:"CERT", value:"236045");
 script_name(english:"Cisco IOS Firewall Authentication Proxy for FTP and Telnet Sessions Buffer Overflow");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch");
 script_set_attribute(attribute:"description", value:
'The Cisco IOS Firewall Authentication Proxy for FTP and/or Telnet
Sessions feature in specific versions of Cisco IOS software is
vulnerable to a remotely-exploitable buffer overflow condition.
Devices that do not support, or are not configured for Firewall
Authentication Proxy for FTP and/or Telnet Services are not affected.
Devices configured with only Authentication Proxy for HTTP and/or HTTPS
are not affected.
Only devices running certain versions of Cisco IOS are affected.
Cisco has made free software available to address this vulnerability.
There are workarounds available to mitigate the effects of the
vulnerability.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7779e544");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a00805117cb.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?317f31da");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20050907-auth_proxy.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/07");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/09/07");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCsa54608");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20050907-auth_proxy");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2010-2014 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");
 exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
override = 0;

if (version == '12.3(11)YK') flag++;
else if (version == '12.3(8)YH') flag++;
else if (version == '12.3(8)YG1') flag++;
else if (version == '12.3(8)YG') flag++;
else if (version == '12.3(8)YD1') flag++;
else if (version == '12.3(8)YD') flag++;
else if (version == '12.3(8)YA1') flag++;
else if (version == '12.3(8)YA') flag++;
else if (version == '12.3(8)XX1') flag++;
else if (version == '12.3(8)XX') flag++;
else if (version == '12.3(7)XS2') flag++;
else if (version == '12.3(7)XS1') flag++;
else if (version == '12.3(7)XS') flag++;
else if (version == '12.3(7)XR3') flag++;
else if (version == '12.3(7)XR2') flag++;
else if (version == '12.3(7)XR') flag++;
else if (version == '12.3(4)XQ1') flag++;
else if (version == '12.3(4)XQ') flag++;
else if (version == '12.3(11)XL1') flag++;
else if (version == '12.3(11)XL') flag++;
else if (version == '12.3(4)XK3') flag++;
else if (version == '12.3(4)XK2') flag++;
else if (version == '12.3(4)XK1') flag++;
else if (version == '12.3(4)XK') flag++;
else if (version == '12.3(4)XG4') flag++;
else if (version == '12.3(4)XG3') flag++;
else if (version == '12.3(4)XG2') flag++;
else if (version == '12.3(4)XG1') flag++;
else if (version == '12.3(4)XG') flag++;
else if (version == '12.3(2)XF') flag++;
else if (version == '12.3(2)XE3') flag++;
else if (version == '12.3(2)XE2') flag++;
else if (version == '12.3(2)XE1') flag++;
else if (version == '12.3(2)XE') flag++;
else if (version == '12.3(4)XD4') flag++;
else if (version == '12.3(4)XD3') flag++;
else if (version == '12.3(4)XD2') flag++;
else if (version == '12.3(4)XD1') flag++;
else if (version == '12.3(4)XD') flag++;
else if (version == '12.3(2)XC2') flag++;
else if (version == '12.3(2)XC1') flag++;
else if (version == '12.3(2)XC') flag++;
else if (version == '12.3(2)XA4') flag++;
else if (version == '12.3(2)XA3') flag++;
else if (version == '12.3(2)XA2') flag++;
else if (version == '12.3(2)XA1') flag++;
else if (version == '12.3(2)XA') flag++;
else if (version == '12.3(11)T5') flag++;
else if (version == '12.3(11)T4') flag++;
else if (version == '12.3(11)T3') flag++;
else if (version == '12.3(11)T2') flag++;
else if (version == '12.3(11)T') flag++;
else if (version == '12.3(8)T8') flag++;
else if (version == '12.3(8)T7') flag++;
else if (version == '12.3(8)T6') flag++;
else if (version == '12.3(8)T5') flag++;
else if (version == '12.3(8)T4') flag++;
else if (version == '12.3(8)T3') flag++;
else if (version == '12.3(8)T1') flag++;
else if (version == '12.3(8)T') flag++;
else if (version == '12.3(7)T9') flag++;
else if (version == '12.3(7)T8') flag++;
else if (version == '12.3(7)T7') flag++;
else if (version == '12.3(7)T6') flag++;
else if (version == '12.3(7)T4') flag++;
else if (version == '12.3(7)T3') flag++;
else if (version == '12.3(7)T2') flag++;
else if (version == '12.3(7)T1') flag++;
else if (version == '12.3(7)T') flag++;
else if (version == '12.3(4)T9') flag++;
else if (version == '12.3(4)T8') flag++;
else if (version == '12.3(4)T7') flag++;
else if (version == '12.3(4)T6') flag++;
else if (version == '12.3(4)T4') flag++;
else if (version == '12.3(4)T3') flag++;
else if (version == '12.3(4)T2') flag++;
else if (version == '12.3(4)T11') flag++;
else if (version == '12.3(4)T10') flag++;
else if (version == '12.3(4)T1') flag++;
else if (version == '12.3(4)T') flag++;
else if (version == '12.3(2)T9') flag++;
else if (version == '12.3(2)T8') flag++;
else if (version == '12.3(2)T7') flag++;
else if (version == '12.3(2)T6') flag++;
else if (version == '12.3(2)T5') flag++;
else if (version == '12.3(2)T4') flag++;
else if (version == '12.3(2)T3') flag++;
else if (version == '12.3(2)T2') flag++;
else if (version == '12.3(2)T1') flag++;
else if (version == '12.3(2)T') flag++;
else if (version == '12.3(5a)B5') flag++;
else if (version == '12.3(5a)B4') flag++;
else if (version == '12.3(5a)B3') flag++;
else if (version == '12.3(5a)B2') flag++;
else if (version == '12.3(5a)B1') flag++;
else if (version == '12.3(5a)B') flag++;
else if (version == '12.3(3)B1') flag++;
else if (version == '12.3(3)B') flag++;
else if (version == '12.3(1a)B') flag++;
else if (version == '12.3(13)') flag++;
else if (version == '12.3(12a)') flag++;
else if (version == '12.3(12)') flag++;
else if (version == '12.3(10c)') flag++;
else if (version == '12.3(10b)') flag++;
else if (version == '12.3(10a)') flag++;
else if (version == '12.3(10)') flag++;
else if (version == '12.3(9c)') flag++;
else if (version == '12.3(9b)') flag++;
else if (version == '12.3(9a)') flag++;
else if (version == '12.3(9)') flag++;
else if (version == '12.3(6c)') flag++;
else if (version == '12.3(6b)') flag++;
else if (version == '12.3(6a)') flag++;
else if (version == '12.3(6)') flag++;
else if (version == '12.3(5d)') flag++;
else if (version == '12.3(5c)') flag++;
else if (version == '12.3(5b)') flag++;
else if (version == '12.3(5a)') flag++;
else if (version == '12.3(5)') flag++;
else if (version == '12.3(3g)') flag++;
else if (version == '12.3(3f)') flag++;
else if (version == '12.3(3e)') flag++;
else if (version == '12.3(3c)') flag++;
else if (version == '12.3(3b)') flag++;
else if (version == '12.3(3a)') flag++;
else if (version == '12.3(3)') flag++;
else if (version == '12.3(1a)') flag++;
else if (version == '12.3(1)') flag++;
else if (version == '12.2(15)ZL1') flag++;
else if (version == '12.2(15)ZL') flag++;
else if (version == '12.2(13)ZH5') flag++;
else if (version == '12.2(13)ZH4') flag++;
else if (version == '12.2(13)ZH3') flag++;
else if (version == '12.2(13)ZH2') flag++;
else if (version == '12.2(13)ZH1') flag++;
else if (version == '12.2(13)ZH') flag++;
else if (version == '12.2(13)ZF2') flag++;
else if (version == '12.2(13)ZF1') flag++;
else if (version == '12.2(13)ZF') flag++;
else if (version == '12.2(18)SXF4') flag++;
else if (version == '12.2(18)SXF3') flag++;
else if (version == '12.2(18)SXF2') flag++;
else if (version == '12.2(18)SXF1') flag++;
else if (version == '12.2(18)SXF') flag++;
else if (version == '12.2(33)SRA') flag++;
else if (version == '12.2(31)SG') flag++;
else if (version == '12.2(25)SG') flag++;
else if (version == '12.2(25)SEC2') flag++;
else if (version == '12.2(25)SEC1') flag++;
else if (version == '12.2(25)SEC') flag++;
else if (version == '12.2(18)IXB') flag++;
else if (version == '12.2(18)IXA') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"ip\s+auth-proxy\s+", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
