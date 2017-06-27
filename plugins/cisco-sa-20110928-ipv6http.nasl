#TRUSTED 15f698f697b026a6ab8af16202fb4dda12c8db9ffbf05814868bb73e77a4b59bb59290ddaf908fad936ebec7e9b6322db43acffd3903e0774a04a110cf390e6b1f77618107c3853387b5b0de36b656ed4edf59aed6aa817e8fdfdb1d9b94d19b9815ad7e0caeef8c352a1dd1c2678e8e3d14b84082cfe52e63873320cd8257c7e1884a282d312b5fd607102f134a42a943846259e921d503d8ef3206c152f2af9e8fb73c7c032c0452eb0072b93b22b64beb2d2dd81e9334115e20a5ba9bd7615c1229040f1d8add54e889bbce1f2f9102796c8a2b199d2bed552a55792d1dc5988252d08bc3ed624fbf770abcd774b8759f39eb3068c7a4fd2f21b5d72b97a7ed7a1dced0295a878cf0447e7a08413200d9bfd012dcbef31fc215eb20a843f2e4225b71581751b5b95120c46e161205dcc5e4a17fc50abad6fe7ca5138a579671555b84a60735cdd40d42f11a3d9e40acd276beb8b8cbddbd0054b8d4dc62cd262bb0708877462a45ab2b2a55f031ccae4029a237a9c0b090fb6bc2f03a6db28de344e9ffb91a9de99ce755471316c043c4bc233e3cbc04f0aa6d9287f420445baf95583f2f169777c1d18d44b0988e5b6cde1bd150a878929e7b8c6db80328fd25cef127640ead0d5cf188f0ca422d7a49936faa3535988ad7bbe69549c306f4f345c073bc2d5c1d44b49ed9def9655138c13a08d132e33acda8f64b641d46
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20110928-ipv6.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(56316);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/03");

  script_cve_id("CVE-2011-0944");
  script_bugtraq_id(49821);
  script_osvdb_id(76008);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtj41194");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20110928-ipv6");

  script_name(english:"Cisco IOS Software IPv6 Denial of Service Vulnerability (cisco-sa-20110928-ipv6)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Cisco IOS Software contains a vulnerability in the IP version 6 (IPv6)
protocol stack implementation that could allow an unauthenticated,
remote attacker to cause a reload of an affected device that has IPv6
operation enabled. The vulnerability is triggered when an affected
device processes a malformed IPv6 packet. Cisco has released free
software updates that address this vulnerability. There are no
workarounds to mitigate this vulnerability."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20110928-ipv6
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bce668d3"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20110928-ipv6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/29");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
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
if ( version == '12.2(33)SRE' ) flag++;
if ( version == '12.2(33)SRE0a' ) flag++;
if ( version == '12.2(33)SRE1' ) flag++;
if ( version == '12.2(33)SRE2' ) flag++;
if ( version == '12.2(33)SRE3' ) flag++;
if ( version == '12.2(33)XNE' ) flag++;
if ( version == '12.2(33)XNE1' ) flag++;
if ( version == '12.2(33)XNE1xb' ) flag++;
if ( version == '12.2(33)XNE2' ) flag++;
if ( version == '12.2(33)XNE3' ) flag++;
if ( version == '12.2(33)XNF' ) flag++;
if ( version == '12.2(33)XNF1' ) flag++;
if ( version == '12.2(33)XNF2' ) flag++;
if ( version == '12.4(24)GC1' ) flag++;
if ( version == '12.4(24)GC3' ) flag++;
if ( version == '12.4(24)GC3a' ) flag++;
if ( version == '12.4(24)T' ) flag++;
if ( version == '12.4(24)T1' ) flag++;
if ( version == '12.4(24)T2' ) flag++;
if ( version == '12.4(24)T3' ) flag++;
if ( version == '12.4(24)T4' ) flag++;
if ( version == '15.0(1)M' ) flag++;
if ( version == '15.0(1)M1' ) flag++;
if ( version == '15.0(1)M2' ) flag++;
if ( version == '15.0(1)M3' ) flag++;
if ( version == '15.0(1)M4' ) flag++;
if ( version == '15.0(1)M5' ) flag++;
if ( version == '15.0(1)M6' ) flag++;
if ( version == '15.0(1)MR' ) flag++;
if ( version == '15.0(1)S' ) flag++;
if ( version == '15.0(1)S1' ) flag++;
if ( version == '15.0(1)S2' ) flag++;
if ( version == '15.0(1)S3a' ) flag++;
if ( version == '15.0(1)XA' ) flag++;
if ( version == '15.0(1)XA1' ) flag++;
if ( version == '15.0(1)XA2' ) flag++;
if ( version == '15.0(1)XA3' ) flag++;
if ( version == '15.0(1)XA4' ) flag++;
if ( version == '15.0(1)XA5' ) flag++;
if ( version == '15.0(2)MR' ) flag++;
if ( version == '15.1(1)S' ) flag++;
if ( version == '15.1(1)S1' ) flag++;
if ( version == '15.1(1)S2' ) flag++;
if ( version == '15.1(1)SA1' ) flag++;
if ( version == '15.1(1)SA2' ) flag++;
if ( version == '15.1(1)T' ) flag++;
if ( version == '15.1(1)T1' ) flag++;
if ( version == '15.1(1)T2' ) flag++;
if ( version == '15.1(1)T3' ) flag++;
if ( version == '15.1(1)XB' ) flag++;
if ( version == '15.1(1)XB1' ) flag++;
if ( version == '15.1(1)XB2' ) flag++;
if ( version == '15.1(1)XB3' ) flag++;
if ( version == '15.1(2)GC' ) flag++;
if ( version == '15.1(2)GC1' ) flag++;
if ( version == '15.1(2)S' ) flag++;
if ( version == '15.1(2)S1' ) flag++;
if ( version == '15.1(2)T' ) flag++;
if ( version == '15.1(2)T0a' ) flag++;
if ( version == '15.1(2)T1' ) flag++;
if ( version == '15.1(2)T2' ) flag++;
if ( version == '15.1(2)T2a' ) flag++;
if ( version == '15.1(2)T3' ) flag++;
if ( version == '15.1(3)T' ) flag++;
if ( version == '15.1(3)T1' ) flag++;
if ( version == '15.1(4)M' ) flag++;
if ( version == '15.1(4)M0a' ) flag++;
if ( version == '15.1(4)M0b' ) flag++;
if ( version == '15.1(4)XB4' ) flag++;
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"ipv6\s+address", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"ipv6\s+enable", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
