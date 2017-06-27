#TRUSTED 8071060ec5f7a05f26bf6a323e0e7425e4675cd589111991b9ac28579b4f407d2a910b05b0916153f5a158d684ca6dcb75a27b7ca672011d1ed5dd5682cd5885bd8110dbb23f215fde5b4972e035a6e1a5276d05d060a2897acc2aa403298b7ac3e74ead39941a42ec2b6d7f021826ea83f93644efbd5ebf69be9034c0e0eab426ba107106b6972a801a9e3128384028f60e3d76470f840f75e47a7d376ffe75e5baaa02fda539c741de44d468d3a594effb061fc7bf3f21f0dbde897a216f06988e6029bbd0b76a7395506a58f88c10c70e0cfc761d16cf4da2a96633c527b3661d8d508d67c465b969f2f07e17fa62bb3f58f5008275a21a21d66e2a72fafd0ebdd305f38ca0fbbcb8656d77b8d1cc3e31f9ecd7464282cb7a39075a82895d17d20f14104a1fbd7d4f6fd3019a235a28e10dac01a81ecfd2d3525f00eae173347d2d29dcb054968e2c80e63232656a5356558b4159bd59fa48b68e11054717f9d69ac2a92ad8baef783a2c3be02aa2f9fcce404df0fe700ae7cae09dde329425f46e846a8a0723d4b648840d423653cfad5fb8394d927dc6d820f44ae289c4cfdf10d5873f26d89537094d14953ae8c5ca8b0911d9a8b96d0895fcb8237b89e27e00b519997d6c080368db22b45848959b8264a1183f407a4e8d4d0e663bd9a925f549c7ff62d9adeacc6423cb787f0986351d956b24cb8dae92bb08f274db
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a0080af811b.shtml

include("compat.inc");

if (description)
{
 script_id(49046);
 script_version("1.17");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");
 script_cve_id("CVE-2009-2870");
 script_bugtraq_id(36499);
 script_osvdb_id(58343);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsx25880");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20090923-sip");
 script_name(english:"Cisco IOS Software Session Initiation Protocol Denial of Service Vulnerability (cisco-sa-20090923-sip)");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'A vulnerability exists in the Session Initiation Protocol (SIP)
implementation in Cisco IOS Software that could allow an
unauthenticated attacker to cause a denial of service (DoS) condition
on an affected device when the Cisco Unified Border Element feature is
enabled.
 Cisco has released free software updates that address this
vulnerability. For devices that must run SIP there are no workarounds;
however, mitigations are available to limit exposure of the
vulnerability.
');
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20090923-sip
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b08fdf59");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a0080af811b.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?6e51f7b2");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20090923-sip.");
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

if (version == '12.4(22)YB') flag++;
else if (version == '12.4(20)YA3') flag++;
else if (version == '12.4(20)YA2') flag++;
else if (version == '12.4(20)YA1') flag++;
else if (version == '12.4(20)YA') flag++;
else if (version == '12.4(15)XZ2') flag++;
else if (version == '12.4(15)XZ1') flag++;
else if (version == '12.4(15)XZ') flag++;
else if (version == '12.4(15)XY5') flag++;
else if (version == '12.4(15)XY4') flag++;
else if (version == '12.4(15)XY3') flag++;
else if (version == '12.4(15)XY2') flag++;
else if (version == '12.4(15)XY1') flag++;
else if (version == '12.4(15)XY') flag++;
else if (version == '12.4(11)XW9') flag++;
else if (version == '12.4(11)XW8') flag++;
else if (version == '12.4(11)XW7') flag++;
else if (version == '12.4(11)XW6') flag++;
else if (version == '12.4(11)XW5') flag++;
else if (version == '12.4(11)XW4') flag++;
else if (version == '12.4(11)XW3') flag++;
else if (version == '12.4(11)XW2') flag++;
else if (version == '12.4(11)XW10') flag++;
else if (version == '12.4(11)XW1') flag++;
else if (version == '12.4(11)XW') flag++;
else if (version == '12.4(11)XV1') flag++;
else if (version == '12.4(11)XV') flag++;
else if (version == '12.4(6)XT2') flag++;
else if (version == '12.4(6)XT1') flag++;
else if (version == '12.4(6)XT') flag++;
else if (version == '12.4(6)XP') flag++;
else if (version == '12.4(15)XM2') flag++;
else if (version == '12.4(15)XM1') flag++;
else if (version == '12.4(15)XL4') flag++;
else if (version == '12.4(15)XL3') flag++;
else if (version == '12.4(15)XL2') flag++;
else if (version == '12.4(15)XL1') flag++;
else if (version == '12.4(15)XL') flag++;
else if (version == '12.4(11)XJ4') flag++;
else if (version == '12.4(11)XJ3') flag++;
else if (version == '12.4(11)XJ2') flag++;
else if (version == '12.4(11)XJ') flag++;
else if (version == '12.4(6)XE3') flag++;
else if (version == '12.4(6)XE2') flag++;
else if (version == '12.4(6)XE1') flag++;
else if (version == '12.4(6)XE') flag++;
else if (version == '12.4(4)XD9') flag++;
else if (version == '12.4(4)XD8') flag++;
else if (version == '12.4(4)XD7') flag++;
else if (version == '12.4(4)XD5') flag++;
else if (version == '12.4(4)XD4') flag++;
else if (version == '12.4(4)XD2') flag++;
else if (version == '12.4(4)XD12') flag++;
else if (version == '12.4(4)XD11') flag++;
else if (version == '12.4(4)XD10') flag++;
else if (version == '12.4(4)XD1') flag++;
else if (version == '12.4(4)XD') flag++;
else if (version == '12.4(4)XC7') flag++;
else if (version == '12.4(4)XC6') flag++;
else if (version == '12.4(4)XC5') flag++;
else if (version == '12.4(4)XC4') flag++;
else if (version == '12.4(4)XC3') flag++;
else if (version == '12.4(4)XC2') flag++;
else if (version == '12.4(4)XC1') flag++;
else if (version == '12.4(4)XC') flag++;
else if (version == '12.4(2)XB9') flag++;
else if (version == '12.4(2)XB8') flag++;
else if (version == '12.4(2)XB7') flag++;
else if (version == '12.4(2)XB6') flag++;
else if (version == '12.4(2)XB5') flag++;
else if (version == '12.4(2)XB4') flag++;
else if (version == '12.4(2)XB3') flag++;
else if (version == '12.4(2)XB2') flag++;
else if (version == '12.4(2)XB10') flag++;
else if (version == '12.4(2)XB1') flag++;
else if (version == '12.4(2)XB') flag++;
else if (version == '12.4(2)XA2') flag++;
else if (version == '12.4(2)XA1') flag++;
else if (version == '12.4(2)XA') flag++;
else if (version == '12.4(24)T') flag++;
else if (version == '12.4(22)T1') flag++;
else if (version == '12.4(22)T') flag++;
else if (version == '12.4(20)T2') flag++;
else if (version == '12.4(20)T1') flag++;
else if (version == '12.4(20)T') flag++;
else if (version == '12.4(15)T9') flag++;
else if (version == '12.4(15)T8') flag++;
else if (version == '12.4(15)T7') flag++;
else if (version == '12.4(15)T6') flag++;
else if (version == '12.4(15)T5') flag++;
else if (version == '12.4(15)T4') flag++;
else if (version == '12.4(15)T3') flag++;
else if (version == '12.4(15)T2') flag++;
else if (version == '12.4(15)T1') flag++;
else if (version == '12.4(15)T') flag++;
else if (version == '12.4(11)T4') flag++;
else if (version == '12.4(11)T3') flag++;
else if (version == '12.4(11)T2') flag++;
else if (version == '12.4(11)T1') flag++;
else if (version == '12.4(11)T') flag++;
else if (version == '12.4(9)T7') flag++;
else if (version == '12.4(9)T6') flag++;
else if (version == '12.4(9)T5') flag++;
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
else if (version == '12.4(6)T11') flag++;
else if (version == '12.4(6)T10') flag++;
else if (version == '12.4(6)T1') flag++;
else if (version == '12.4(6)T') flag++;
else if (version == '12.4(4)T8') flag++;
else if (version == '12.4(4)T7') flag++;
else if (version == '12.4(4)T6') flag++;
else if (version == '12.4(4)T5') flag++;
else if (version == '12.4(4)T4') flag++;
else if (version == '12.4(4)T3') flag++;
else if (version == '12.4(4)T2') flag++;
else if (version == '12.4(4)T1') flag++;
else if (version == '12.4(4)T') flag++;
else if (version == '12.4(2)T6') flag++;
else if (version == '12.4(2)T5') flag++;
else if (version == '12.4(2)T4') flag++;
else if (version == '12.4(2)T3') flag++;
else if (version == '12.4(2)T2') flag++;
else if (version == '12.4(2)T1') flag++;
else if (version == '12.4(2)T') flag++;
else if (version == '12.4(19)MR2') flag++;
else if (version == '12.4(19)MR1') flag++;
else if (version == '12.4(19)MR') flag++;
else if (version == '12.4(16)MR2') flag++;
else if (version == '12.4(16)MR1') flag++;
else if (version == '12.4(16)MR') flag++;
else if (version == '12.4(12)MR2') flag++;
else if (version == '12.4(12)MR1') flag++;
else if (version == '12.4(12)MR') flag++;
else if (version == '12.4(11)MR') flag++;
else if (version == '12.4(9)MR') flag++;
else if (version == '12.4(6)MR1') flag++;
else if (version == '12.4(6)MR') flag++;
else if (version == '12.4(4)MR1') flag++;
else if (version == '12.4(4)MR') flag++;
else if (version == '12.4(2)MR1') flag++;
else if (version == '12.4(2)MR') flag++;
else if (version == '12.4(22)GC1') flag++;
else if (version == '12.3(14)YT1') flag++;
else if (version == '12.3(14)YT') flag++;
else if (version == '12.3(11)YS2') flag++;
else if (version == '12.3(11)YK2') flag++;
else if (version == '12.3(11)YK1') flag++;
else if (version == '12.3(11)YK') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_processes", "show processes");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"SIP", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
