#TRUSTED 7be23c407dc482d27e36518fd699da5301aa113b9b5cda7c1fa35b7c704a1466dedc4414af297c97a193622c4b8efb7a6d809e015975c16669c80e03e746e34afc6ec89395281fad8c52b48ec85ba672a4054ff2caccd67ac037b3bd42bf8a1b3245ef019827a86c4b7102e02a8657aa29c525875776d4f5cf08ab39a79ab6ffb364e30b0b3d436f7a8e294607d827f6abbad97834eaddc3529cd6a2f502c0136a5457e7e9f8b0d3da62980e5f9568f63c946f2746adb736ac51fdd3a63f62dc113ee8a6b630e4789352ee9a8cf7841e95c3b7fd450db86f86b7078634f311a9ded526f89d40071d2f5c8e11cfd57da58a5c86a00d25296ae81f401473fe753de0129dcc28ff3b2c2b8113c94329251c40f3ad8944a367a35d59b15240def3a162649c1597a4f8cb4bc01b1aa7e669d543420c2d3fbf4fc6a7342561086a49d2ad0d7c5ee04606b33b754ee73bfdf2b82215fded2b343be468b1658cd13e1137be0022d15399a1731d642f545a93a2ea2abc858dd3674fad567d1ec62a108ff02398452d9ad88dfe14a022d915571b2190bc2b1a7d11a7c9fb5fc97c35ab2088c28343854cbd13333ca3c7acb5dbb728b55783c35904dca19b1cd398c2b903642792a8d6fef6cd16ff0e42cec33d5ec3c3fb6ac964261c31a8524d0a738e8d25b41d44e3dadff82b935811781645f1b86310d623b117ee21a7776b0bf8ce094c
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a0080a0148e.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49024);
 script_version("1.15");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");
 script_cve_id("CVE-2008-3810", "CVE-2008-3811");
 script_bugtraq_id(31359);
 script_osvdb_id(48735, 48736);
 script_name(english:"Cisco IOS NAT Skinny Call Control Protocol Vulnerability");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'A series of segmented Skinny Call Control Protocol (SCCP) messages may
cause a Cisco IOS device that is configured with the Network Address
Translation (NAT) SCCP Fragmentation Support feature to reload.
 Cisco has released free software updates that address this
vulnerability. A workaround that mitigates this vulnerability is
available.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df1001e6");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a0080a0148e.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?d27e6f19");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20080924-sccp.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20);
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/09/24");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/09/24");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCsg22426");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsi17020");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20080924-sccp");
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

if (version == '12.4(11)XW6') flag++;
else if (version == '12.4(11)XW5') flag++;
else if (version == '12.4(11)XW4') flag++;
else if (version == '12.4(11)XW3') flag++;
else if (version == '12.4(11)XW2') flag++;
else if (version == '12.4(11)XW1') flag++;
else if (version == '12.4(11)XW') flag++;
else if (version == '12.4(11)XV1') flag++;
else if (version == '12.4(11)XV') flag++;
else if (version == '12.4(6)XT2') flag++;
else if (version == '12.4(6)XT1') flag++;
else if (version == '12.4(6)XT') flag++;
else if (version == '12.4(6)XP') flag++;
else if (version == '12.4(15)XN') flag++;
else if (version == '12.4(15)XM') flag++;
else if (version == '12.4(15)XL1') flag++;
else if (version == '12.4(15)XL') flag++;
else if (version == '12.4(14)XK') flag++;
else if (version == '12.4(11)XJ4') flag++;
else if (version == '12.4(11)XJ3') flag++;
else if (version == '12.4(11)XJ2') flag++;
else if (version == '12.4(11)XJ') flag++;
else if (version == '12.4(9)XG4') flag++;
else if (version == '12.4(9)XG3') flag++;
else if (version == '12.4(9)XG2') flag++;
else if (version == '12.4(9)XG1') flag++;
else if (version == '12.4(9)XG') flag++;
else if (version == '12.4(15)XF') flag++;
else if (version == '12.4(6)XE3') flag++;
else if (version == '12.4(6)XE2') flag++;
else if (version == '12.4(6)XE1') flag++;
else if (version == '12.4(6)XE') flag++;
else if (version == '12.4(4)XC7') flag++;
else if (version == '12.4(4)XC6') flag++;
else if (version == '12.4(4)XC5') flag++;
else if (version == '12.4(4)XC4') flag++;
else if (version == '12.4(4)XC3') flag++;
else if (version == '12.4(4)XC2') flag++;
else if (version == '12.4(4)XC1') flag++;
else if (version == '12.4(4)XC') flag++;
else if (version == '12.4(15)T1') flag++;
else if (version == '12.4(15)T') flag++;
else if (version == '12.4(11)T3') flag++;
else if (version == '12.4(11)T2') flag++;
else if (version == '12.4(11)T1') flag++;
else if (version == '12.4(11)T') flag++;
else if (version == '12.4(9)T4') flag++;
else if (version == '12.4(9)T3') flag++;
else if (version == '12.4(9)T2') flag++;
else if (version == '12.4(9)T1') flag++;
else if (version == '12.4(9)T') flag++;
else if (version == '12.4(6)T9') flag++;
else if (version == '12.4(6)T8') flag++;
else if (version == '12.4(6)T7') flag++;
else if (version == '12.4(6)T6') flag++;
else if (version == '12.4(6)T5') flag++;
else if (version == '12.4(6)T4') flag++;
else if (version == '12.4(6)T3') flag++;
else if (version == '12.4(6)T2') flag++;
else if (version == '12.4(6)T10') flag++;
else if (version == '12.4(6)T1') flag++;
else if (version == '12.4(6)T') flag++;
else if (version == '12.4(15)SW1') flag++;
else if (version == '12.4(15)SW') flag++;
else if (version == '12.4(11)SW3') flag++;
else if (version == '12.4(11)SW2') flag++;
else if (version == '12.4(11)SW1') flag++;
else if (version == '12.4(11)SW') flag++;
else if (version == '12.4(12)MR2') flag++;
else if (version == '12.4(12)MR1') flag++;
else if (version == '12.4(12)MR') flag++;
else if (version == '12.4(11)MR') flag++;
else if (version == '12.4(9)MR') flag++;
else if (version == '12.4(6)MR1') flag++;
else if (version == '12.4(6)MR') flag++;
else if (version == '12.4(11)MD3') flag++;
else if (version == '12.4(11)MD2') flag++;
else if (version == '12.4(11)MD1') flag++;
else if (version == '12.4(11)MD') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if ( (preg(pattern:"\s+ip\s+nat\s+inside", multiline:TRUE, string:buf)) && (preg(pattern:"\s+ip\s+nat\s+outside", multiline:TRUE, string:buf)) ) { flag = 1; }
      if (preg(pattern:"\s+ip\s+nat\s+enable", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
