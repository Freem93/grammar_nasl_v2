#TRUSTED 6ff474a5e793ffd1b557202debe4abb488d3927704a84bfa58f02d18003dcad89d8550724757d98f9f1295c0a60e6ef937c63e8c304a19607f37f148a39d1414d3e23c7b7bf1dd1b855762614444d1cba016b2cce2ac6de56e9a438d05e5004c812eccaef270c5d381b0c4298bb52e38301a6ab24061bcb0e29b08e792e284bf7067d77de988bb32a5a9f867e083183611c32ded2ade87fe48f395e762df979d2f9dcbadf73d83f63f0ecaaa56d656ecd430222c76a981b4b308f4c467b138c927287ad96cf368e12c2bb9c20f676abc4bdb7ae169f09013025ef78737574740a48ec1c8eaf55409be9ef23bb04ab9b408a8cbcdd287199ed4f71c3a483022fcf0145bc1a6b88eb1f7f6c5b88a6ed1f827fda941508e47b352e8e1422ab67575338d546594472b381375ab30f010e65abe0c675272ccff2d9808d0bb714900d0503e92bd8d354b79085c2c0c902ea12584f5cb785fa059fefcd3348d7f539d2e970b16bea3772a198f007c14ea5efce3ed0bc9afd4394660e51b9e10ea9131cb6a9bb5856ae996d728fc44f1915c7f72ea8fe0a8d61e2ad568e64e0e24c0c1ea18242bf84858c32eb9b3b69b1aa7b413dd53914cfad3f8edd4d24d81ed4964ceb6939261db3bd26a9181fd24b02c026f2da6d451bbef0994d36ef2299468c1f8ad4a2d71734785da7a0a1c61511eb1969ac50ac9c2a1a63839e3077e51d60dc1
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20100324-sccp.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(49053);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/03");

  script_cve_id("CVE-2010-0584");
  script_osvdb_id(63187);
  script_xref(name:"CISCO-BUG-ID", value:"CSCsy09250");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20100324-sccp");

  script_name(english:"Cisco IOS Software NAT Skinny Call Control Protocol Vulnerability (cisco-sa-20100324-sccp)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Skinny Client Control Protocol (SCCP) crafted messages may cause a
Cisco IOS device that is configured with the Network Address
Translation (NAT) SCCP Fragmentation Support feature to reload. Cisco
has released free software updates that address this vulnerability. A
workaround that mitigates this vulnerability is available."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20100324-sccp
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e259c3f8"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20100324-sccp."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if ( version == '12.4(11)MD' ) flag++;
if ( version == '12.4(11)MD1' ) flag++;
if ( version == '12.4(11)MD2' ) flag++;
if ( version == '12.4(11)MD3' ) flag++;
if ( version == '12.4(11)MD4' ) flag++;
if ( version == '12.4(11)MD5' ) flag++;
if ( version == '12.4(11)MD6' ) flag++;
if ( version == '12.4(11)MD7' ) flag++;
if ( version == '12.4(11)MD8' ) flag++;
if ( version == '12.4(11)MD9' ) flag++;
if ( version == '12.4(11)MR' ) flag++;
if ( version == '12.4(11)SW' ) flag++;
if ( version == '12.4(11)SW1' ) flag++;
if ( version == '12.4(11)SW2' ) flag++;
if ( version == '12.4(11)SW3' ) flag++;
if ( version == '12.4(11)T' ) flag++;
if ( version == '12.4(11)T1' ) flag++;
if ( version == '12.4(11)T2' ) flag++;
if ( version == '12.4(11)T3' ) flag++;
if ( version == '12.4(11)T4' ) flag++;
if ( version == '12.4(11)XJ' ) flag++;
if ( version == '12.4(11)XJ1' ) flag++;
if ( version == '12.4(11)XJ2' ) flag++;
if ( version == '12.4(11)XJ3' ) flag++;
if ( version == '12.4(11)XJ4' ) flag++;
if ( version == '12.4(11)XJ5' ) flag++;
if ( version == '12.4(11)XJ6' ) flag++;
if ( version == '12.4(11)XV' ) flag++;
if ( version == '12.4(11)XV1' ) flag++;
if ( version == '12.4(11)XW' ) flag++;
if ( version == '12.4(11)XW1' ) flag++;
if ( version == '12.4(11)XW10' ) flag++;
if ( version == '12.4(11)XW2' ) flag++;
if ( version == '12.4(11)XW3' ) flag++;
if ( version == '12.4(11)XW4' ) flag++;
if ( version == '12.4(11)XW5' ) flag++;
if ( version == '12.4(11)XW6' ) flag++;
if ( version == '12.4(11)XW7' ) flag++;
if ( version == '12.4(11)XW8' ) flag++;
if ( version == '12.4(11)XW9' ) flag++;
if ( version == '12.4(12)MR' ) flag++;
if ( version == '12.4(12)MR1' ) flag++;
if ( version == '12.4(12)MR2' ) flag++;
if ( version == '12.4(14)XK' ) flag++;
if ( version == '12.4(15)MD' ) flag++;
if ( version == '12.4(15)MD1' ) flag++;
if ( version == '12.4(15)MD2' ) flag++;
if ( version == '12.4(15)MD3' ) flag++;
if ( version == '12.4(15)SW' ) flag++;
if ( version == '12.4(15)SW1' ) flag++;
if ( version == '12.4(15)SW2' ) flag++;
if ( version == '12.4(15)SW3' ) flag++;
if ( version == '12.4(15)SW4' ) flag++;
if ( version == '12.4(15)T' ) flag++;
if ( version == '12.4(15)T1' ) flag++;
if ( version == '12.4(15)T2' ) flag++;
if ( version == '12.4(15)T3' ) flag++;
if ( version == '12.4(15)T4' ) flag++;
if ( version == '12.4(15)T5' ) flag++;
if ( version == '12.4(15)T6' ) flag++;
if ( version == '12.4(15)T6a' ) flag++;
if ( version == '12.4(15)T7' ) flag++;
if ( version == '12.4(15)T8' ) flag++;
if ( version == '12.4(15)T9' ) flag++;
if ( version == '12.4(15)XF' ) flag++;
if ( version == '12.4(15)XL' ) flag++;
if ( version == '12.4(15)XL1' ) flag++;
if ( version == '12.4(15)XL2' ) flag++;
if ( version == '12.4(15)XL3' ) flag++;
if ( version == '12.4(15)XL4' ) flag++;
if ( version == '12.4(15)XL5' ) flag++;
if ( version == '12.4(15)XM' ) flag++;
if ( version == '12.4(15)XM1' ) flag++;
if ( version == '12.4(15)XM2' ) flag++;
if ( version == '12.4(15)XM3' ) flag++;
if ( version == '12.4(15)XN' ) flag++;
if ( version == '12.4(15)XQ' ) flag++;
if ( version == '12.4(15)XQ1' ) flag++;
if ( version == '12.4(15)XQ2' ) flag++;
if ( version == '12.4(15)XQ2a' ) flag++;
if ( version == '12.4(15)XQ2b' ) flag++;
if ( version == '12.4(15)XQ2c' ) flag++;
if ( version == '12.4(15)XQ3' ) flag++;
if ( version == '12.4(15)XQ4' ) flag++;
if ( version == '12.4(15)XR' ) flag++;
if ( version == '12.4(15)XR1' ) flag++;
if ( version == '12.4(15)XR2' ) flag++;
if ( version == '12.4(15)XR3' ) flag++;
if ( version == '12.4(15)XR4' ) flag++;
if ( version == '12.4(15)XR5' ) flag++;
if ( version == '12.4(15)XR6' ) flag++;
if ( version == '12.4(15)XR7' ) flag++;
if ( version == '12.4(15)XR8' ) flag++;
if ( version == '12.4(15)XY' ) flag++;
if ( version == '12.4(15)XY1' ) flag++;
if ( version == '12.4(15)XY2' ) flag++;
if ( version == '12.4(15)XY3' ) flag++;
if ( version == '12.4(15)XY4' ) flag++;
if ( version == '12.4(15)XY5' ) flag++;
if ( version == '12.4(15)XZ' ) flag++;
if ( version == '12.4(15)XZ1' ) flag++;
if ( version == '12.4(15)XZ2' ) flag++;
if ( version == '12.4(16)MR' ) flag++;
if ( version == '12.4(16)MR1' ) flag++;
if ( version == '12.4(16)MR2' ) flag++;
if ( version == '12.4(19)MR' ) flag++;
if ( version == '12.4(19)MR1' ) flag++;
if ( version == '12.4(19)MR2' ) flag++;
if ( version == '12.4(20)MR' ) flag++;
if ( version == '12.4(20)MR2' ) flag++;
if ( version == '12.4(20)T' ) flag++;
if ( version == '12.4(20)T1' ) flag++;
if ( version == '12.4(20)T2' ) flag++;
if ( version == '12.4(20)T3' ) flag++;
if ( version == '12.4(20)YA' ) flag++;
if ( version == '12.4(20)YA1' ) flag++;
if ( version == '12.4(20)YA2' ) flag++;
if ( version == '12.4(20)YA3' ) flag++;
if ( version == '12.4(22)GC1' ) flag++;
if ( version == '12.4(22)MD' ) flag++;
if ( version == '12.4(22)MD1' ) flag++;
if ( version == '12.4(22)MDA' ) flag++;
if ( version == '12.4(22)MDA1' ) flag++;
if ( version == '12.4(22)MF' ) flag++;
if ( version == '12.4(22)T' ) flag++;
if ( version == '12.4(22)T1' ) flag++;
if ( version == '12.4(22)T2' ) flag++;
if ( version == '12.4(22)XR' ) flag++;
if ( version == '12.4(22)XR1' ) flag++;
if ( version == '12.4(22)XR2' ) flag++;
if ( version == '12.4(22)YB' ) flag++;
if ( version == '12.4(22)YB1' ) flag++;
if ( version == '12.4(22)YB4' ) flag++;
if ( version == '12.4(22)YB5' ) flag++;
if ( version == '12.4(22)YD' ) flag++;
if ( version == '12.4(22)YD1' ) flag++;
if ( version == '12.4(22)YD2' ) flag++;
if ( version == '12.4(22)YE' ) flag++;
if ( version == '12.4(22)YE1' ) flag++;
if ( version == '12.4(24)GC1' ) flag++;
if ( version == '12.4(24)T' ) flag++;
if ( version == '12.4(24)T1' ) flag++;
if ( version == '12.4(24)YG1' ) flag++;
if ( version == '12.4(4)XC' ) flag++;
if ( version == '12.4(4)XC1' ) flag++;
if ( version == '12.4(4)XC2' ) flag++;
if ( version == '12.4(4)XC3' ) flag++;
if ( version == '12.4(4)XC4' ) flag++;
if ( version == '12.4(4)XC5' ) flag++;
if ( version == '12.4(4)XC6' ) flag++;
if ( version == '12.4(4)XC7' ) flag++;
if ( version == '12.4(6)MR' ) flag++;
if ( version == '12.4(6)MR1' ) flag++;
if ( version == '12.4(6)T' ) flag++;
if ( version == '12.4(6)T1' ) flag++;
if ( version == '12.4(6)T10' ) flag++;
if ( version == '12.4(6)T11' ) flag++;
if ( version == '12.4(6)T12' ) flag++;
if ( version == '12.4(6)T2' ) flag++;
if ( version == '12.4(6)T3' ) flag++;
if ( version == '12.4(6)T4' ) flag++;
if ( version == '12.4(6)T5' ) flag++;
if ( version == '12.4(6)T5a' ) flag++;
if ( version == '12.4(6)T5b' ) flag++;
if ( version == '12.4(6)T5c' ) flag++;
if ( version == '12.4(6)T5d' ) flag++;
if ( version == '12.4(6)T5e' ) flag++;
if ( version == '12.4(6)T5f' ) flag++;
if ( version == '12.4(6)T6' ) flag++;
if ( version == '12.4(6)T7' ) flag++;
if ( version == '12.4(6)T8' ) flag++;
if ( version == '12.4(6)T9' ) flag++;
if ( version == '12.4(6)XE' ) flag++;
if ( version == '12.4(6)XE1' ) flag++;
if ( version == '12.4(6)XE2' ) flag++;
if ( version == '12.4(6)XE3' ) flag++;
if ( version == '12.4(6)XE4' ) flag++;
if ( version == '12.4(6)XP' ) flag++;
if ( version == '12.4(6)XT' ) flag++;
if ( version == '12.4(6)XT1' ) flag++;
if ( version == '12.4(6)XT2' ) flag++;
if ( version == '12.4(9)MR' ) flag++;
if ( version == '12.4(9)T' ) flag++;
if ( version == '12.4(9)T0a' ) flag++;
if ( version == '12.4(9)T1' ) flag++;
if ( version == '12.4(9)T2' ) flag++;
if ( version == '12.4(9)T3' ) flag++;
if ( version == '12.4(9)T4' ) flag++;
if ( version == '12.4(9)T5' ) flag++;
if ( version == '12.4(9)T6' ) flag++;
if ( version == '12.4(9)T7' ) flag++;
if ( version == '12.4(9)XG' ) flag++;
if ( version == '12.4(9)XG1' ) flag++;
if ( version == '12.4(9)XG2' ) flag++;
if ( version == '12.4(9)XG3' ) flag++;
if ( version == '12.4(9)XG4' ) flag++;
if ( version == '12.4(9)XG5' ) flag++;
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if ( (preg(pattern:"\n\s*ip nat inside\n", multiline:TRUE, string:buf)) && (preg(pattern:"\n\s*ip nat outside\n", multiline:TRUE, string:buf)) ) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_nat_nvi_statistics", "show ip nat nvi statistics");
    if (check_cisco_result(buf)) { flag = 1; }
    else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
