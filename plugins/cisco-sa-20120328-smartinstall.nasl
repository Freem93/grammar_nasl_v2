#TRUSTED 4a0e9d5a22bb9644a3bac4df4319c3b0b0672fe39b6e3d221aed451ab51b56593a1ec90d0b3c8b6d89af34db387d7824ad76001ace86c1f434543dd323123e13437e2f1e03f448ffe127b6c493f600d5832e663b8ad87fd5ae45a332e72cd4f205ff743449642fa9afd802a24bed6e0a65834bfe955b80d97021c0bcea69304d1b1b088a2a25567f7206f8f4a638f20807e260069d96da065942cc9e035c6e9719e5c5a266cf45927fa8e9c4daaad00c4a3931b4604ec6b79e4d5e798815c5506d8975489b4fc9472bb10877f145b44ffadb9c9ae7cd1d90f24b3b42971b77fcee01106ff00cb3e4491ab4485229d7c2d953c60cab9e4c9748cef9143864459307dca061c917a2b10975745cf2d1a155378692ae0c6520f6849843f4b769688e4f20f84d45595c00c8c993d7845ef10a2869d82199d141991f4ba9d130e8a487b1ea10eb62dce53145f058e7d94a256eeede6c0ea5eb1112066bb9edf597e307cccda10f62d37f76172072b7bf25d0a2b64a01645b42b39ebb2acda761fce7cf95dfa962b348935288f4f1fdc8285fe46cdef3e7c6b45fe279f6aa4d4dace346dbbd45d9924869c051edd4fa66aa90566492e987e537c7235a2496d4f74e426d406597d2dbd1db9426824b41aeed0abc0e44c2474acf050ced6a5c43dff88e41d86757aa03e35f247153423956d569861cd327355687c1d12cad7fa64df97272
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20120328-smartinstall.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(58572);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/03");

  script_cve_id("CVE-2012-0385");
  script_bugtraq_id(52756);
  script_osvdb_id(80694);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtt16051");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120328-smartinstall");

  script_name(english:"Cisco IOS Software Smart Install Denial of Service Vulnerability (cisco-sa-20120328-smartinstall)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Cisco IOS Software contains a vulnerability in the Smart Install
feature that could allow an unauthenticated, remote attacker to cause
a reload of an affected device if the Smart Install feature is
enabled. The vulnerability is triggered when an affected device
processes a malformed Smart Install message on TCP port 4786. Cisco
has released free software updates that address this vulnerability. A
workaround may be available in some versions of Cisco IOS Software if
the Smart Install feature is not needed."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120328-smartinstall
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?12514858"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20120328-smartinstall."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/02");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if ( version == '12.2(52)EX' ) flag++;
if ( version == '12.2(52)EX1' ) flag++;
if ( version == '12.2(52)SE' ) flag++;
if ( version == '12.2(53)EY' ) flag++;
if ( version == '12.2(53)SE' ) flag++;
if ( version == '12.2(53)SE1' ) flag++;
if ( version == '12.2(53)SE2' ) flag++;
if ( version == '12.2(55)EX' ) flag++;
if ( version == '12.2(55)EX1' ) flag++;
if ( version == '12.2(55)EX2' ) flag++;
if ( version == '12.2(55)EX3' ) flag++;
if ( version == '12.2(55)EY' ) flag++;
if ( version == '12.2(55)EZ' ) flag++;
if ( version == '12.2(55)SE' ) flag++;
if ( version == '12.2(55)SE1' ) flag++;
if ( version == '12.2(55)SE2' ) flag++;
if ( version == '12.2(55)SE3' ) flag++;
if ( version == '12.2(55)SE4' ) flag++;
if ( version == '12.2(58)EY' ) flag++;
if ( version == '12.2(58)EY1' ) flag++;
if ( version == '12.2(58)EY2' ) flag++;
if ( version == '12.2(58)SE' ) flag++;
if ( version == '12.2(58)SE1' ) flag++;
if ( version == '12.2(58)SE2' ) flag++;
if ( version == '15.0(1)SE' ) flag++;
if ( version == '15.1(3)T' ) flag++;
if ( version == '15.1(3)T1' ) flag++;
if ( version == '15.1(3)T2' ) flag++;
if ( version == '15.1(4)M' ) flag++;
if ( version == '15.1(4)M0a' ) flag++;
if ( version == '15.1(4)M0b' ) flag++;
if ( version == '15.1(4)M1' ) flag++;
if ( version == '15.1(4)M2' ) flag++;
if ( version == '15.1(4)M3' ) flag++;
if ( version == '15.1(4)M3a' ) flag++;
if ( version == '15.1(4)XB4' ) flag++;
if ( version == '15.1(4)XB5' ) flag++;
if ( version == '15.1(4)XB6' ) flag++;
if ( version == '15.2(1)GC' ) flag++;
if ( version == '15.2(1)GC1' ) flag++;
if ( version == '15.2(1)T' ) flag++;
if ( version == '15.2(1)T1' ) flag++;
if ( version == '15.2(2)T' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_vstack_config", "show vstack config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"Role:\s+\(Client\|Director\)", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}



if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
