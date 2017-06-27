#TRUSTED 32c4dea288ac1b8aa916956cec261d2fe78e924ba89165107ca9bb34e74dcbdbd4182332c7af52fc552143bf6c01465dcdfa6fc8ba1f53f079ad4d35570f3216964ee6983470df6897decb7d71dc14441c8fdfd933e2f91304c951935d881a695ef60275c324dbd9e63d7406ac15fd21fdc1bc7bead73632918836648f43cab88fabe301c0de29d363225dd0b628204002c2d977789de861aedf8e598d70c045a06255d91b6f5850ebffe7c4f9522e4dfbba202e31cccdf3db3503effccac4208451290cf0a0fecd2b9b2cbe905c3d28bd70e4c3bab016780ec7b83e2be0893fb7286e93a66ea1701975ef57a5b20696c73f1529efeb1c71791cbcb0df3a350626790eaeb0372049663d6976e6a3110cd0e5d1792649344a0bbcd8e906ff8454a5bb546a7a7dda49cf242a7a0964768e0e781f3dbda9f00aca13c9faff5b5e4674a8d5eb67a03a9de9ca7b3cda458eea83e9285c8788c4df385ac4ae916784a372ad6b2d16a43739fe488e31b6d6d2a650185b878bb9394ecaad8c6743a0c5f63571514fccb9725efe7c1014a1fea6a7be116a7ee82bc914af39d9fc8081061627e2f1e0db48201047fdb2f0e31573d12b443571c6617914e93f123fefd722d9dbf324f1eb41027e7434272a380111f3547ca995401aba336546a79be104b5af29cb84974f2e45070e3bd7706e7bf4a85396667686e1c796b44cec39b1d98d44
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a0080899636.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49009);
 script_version("1.13");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");
 script_cve_id("CVE-2007-4263");
 script_bugtraq_id(25240);
 script_osvdb_id(36694);
 script_name(english:"Cisco IOS Secure Copy Authorization Bypass Vulnerability");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'The server side of the Secure Copy (SCP) implementation in Cisco
Internetwork Operating System (IOS) contains a vulnerability that
allows any valid user, regardless of privilege level, to transfer files
to and from an IOS device that is configured to be a Secure Copy
server. This vulnerability could allow valid users to retrieve or write
to any file on the device\'s filesystem, including the device\'s saved
configuration. This configuration file may include passwords or other
sensitive information.
 The IOS Secure Copy Server is an optional service that is disabled by
default. Devices that are not specifically configured to enable the IOS
Secure Copy Server service are not affected by this vulnerability.
 This vulnerability does not apply to the IOS Secure Copy Client
feature.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?40b02fb3");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a0080899636.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?c5de8d8a");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20070808-scp.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/08");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/08/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCsc19259");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20070808-scp");
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

if (version == '12.2(18)ZU2') flag++;
else if (version == '12.2(18)ZU1') flag++;
else if (version == '12.2(18)ZU') flag++;
else if (version == '12.2(18)SXF8') flag++;
else if (version == '12.2(18)SXF7') flag++;
else if (version == '12.2(18)SXF6') flag++;
else if (version == '12.2(18)SXF5') flag++;
else if (version == '12.2(18)SXF4') flag++;
else if (version == '12.2(18)SXF3') flag++;
else if (version == '12.2(18)SXF2') flag++;
else if (version == '12.2(18)SXF1') flag++;
else if (version == '12.2(18)SXF') flag++;
else if (version == '12.2(18)SXE6b') flag++;
else if (version == '12.2(18)SXE6a') flag++;
else if (version == '12.2(18)SXE6') flag++;
else if (version == '12.2(18)SXE5') flag++;
else if (version == '12.2(18)SXE4') flag++;
else if (version == '12.2(18)SXE3') flag++;
else if (version == '12.2(18)SXE2') flag++;
else if (version == '12.2(18)SXE1') flag++;
else if (version == '12.2(18)SXE') flag++;
else if (version == '12.2(18)SXD7b') flag++;
else if (version == '12.2(18)SXD7a') flag++;
else if (version == '12.2(18)SXD7') flag++;
else if (version == '12.2(18)SXD6') flag++;
else if (version == '12.2(18)SXD5') flag++;
else if (version == '12.2(18)SXD4') flag++;
else if (version == '12.2(18)SXD3') flag++;
else if (version == '12.2(18)SXD2') flag++;
else if (version == '12.2(18)SXD1') flag++;
else if (version == '12.2(18)SXD') flag++;
else if (version == '12.2(18)IXD') flag++;
else if (version == '12.2(18)IXC') flag++;
else if (version == '12.2(18)IXB2') flag++;
else if (version == '12.2(18)IXB1') flag++;
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
      if (preg(pattern:"ip scp server enable", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
