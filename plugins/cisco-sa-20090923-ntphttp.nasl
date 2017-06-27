#TRUSTED 25a522a5d2f652caab5e5d9e0eb10dbf50bb4bbd9deb0544fdd9d058c699582c69cafb9e6e9120be7f4af703ba51f0d917cbd0a1efa51f516a52adecdd636af91bdad386f7d633ab3b7a1872cac13084c0c7fea43b75ff3cfdc6ab0a2c6d1b3695fac257e809dd459f6b3b7d22093796b179051809bd984313f1bfb68b0f38897e6717ae22cfdeb69c66abe0d24c4d1e0a752ebd294b04e132c5b605a57eae2835e5b959d36d07882c50f168ba743fe6f6b1cc9f42b1f2b1220def09a2fc1097987f4c82b65ef7ebac63caaab678d7bc6eb4354433395932f5f7cf4841a16ad447af6afd442316976df8435c18445ee672d3ce4dee5c83692a1ea35b590dfcaedf7cd15e5adccf1913c73506b5bc76cd189022a86f646c0fb294123e148ade075ef50a21837fb292cb6c71af0586bd75fc4768d57124f815c2eb6590d9ed8702230b28153339f7ccf8bd202051fb11d78d100ae07e15715ba55ae82d2cdac5ed8d379529538e5afb8c3be28e692027892ae0d2498ab141a028e64a1a4b368096ad82404ff2f2a691d9d8069ae20700eb4afb236b4a51126e5e75888298c3239380a3fa9ec80c0243858233b0c09d83b6519eff32053e200c31b020def0f1662b70e92935016200a376ed0885000c19f593938bf6bc5f779254a87b7b4ace7bffb9f60cf0d46483a51545a19ec72b2829e661c4183c822b187d68a151ef1a6fcd
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a0080af8131.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49045);
 script_version("1.15");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");
 script_cve_id("CVE-2009-2869");
 script_bugtraq_id(36502);
 script_osvdb_id(58342);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsu24505");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsv75948");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsw79186");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20090923-ntp");
 script_name(english:"Cisco IOS Software Network Time Protocol Packet Vulnerability - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'Cisco IOS Software with support for Network Time Protocol (NTP)
version (v4) contains a vulnerability processing specific NTP packets
that will result in a reload of the device. This results in a remote
denial of service (DoS) condition on the affected device.
Cisco has released free software updates that address this
vulnerability.
Workarounds that mitigate this vulnerability are available.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?90057cc8");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a0080af8131.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?f9a9c2da");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20090923-ntp.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/23");
 script_set_attribute(attribute:"patch_publication_date", value:"2009/09/23");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
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
override = 0;
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (version == '12.4(22)YE') flag++;
else if (version == '12.4(22)YD') flag++;
else if (version == '12.4(20)YA3') flag++;
else if (version == '12.4(20)YA2') flag++;
else if (version == '12.4(20)YA1') flag++;
else if (version == '12.4(20)YA') flag++;
else if (version == '12.4(15)XZ2') flag++;
else if (version == '12.4(15)XZ1') flag++;
else if (version == '12.4(15)XZ') flag++;
else if (version == '12.4(22)T') flag++;
else if (version == '12.4(20)T1') flag++;
else if (version == '12.4(20)T') flag++;
else if (version == '12.4(22)MD') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"ntp master", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"ntp peer", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"ntp server", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"ntp broadcast client", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"ntp multicast client", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
