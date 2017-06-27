#TRUSTED 8bfdfb0328aa98eef01ef718a2d56165523ab5e033a11745435c4b1b16f41d8af2c4c79213786b9aa0e499fb3d473f1ca6b4451b5d8bd6b213e6fc1c9626546b9ff93f1f585ca8918e8de63c05d4d66bed6a34eb9e0703a7e265f732baf749c3e4e6d797fc30218e08b3962b9683bce926eb08ac875a3a3bba1d157397be31ab2d6d8243c4bba1ed1f6354ced04d77113e2e623b84f98a1a9b822560b2617be3c8079625dbcaef24e72dcac30ba6d5f099c7913101926e36c08bfd8414730570330da173ac4d247ac0fb2e17c7801947d66ffbc8422407a3e57f16e6862f46bc1bf73a5930466bca87324ee5228271a348267906433e445a8cc8effdd73fca017dd71ab99f8accef86ba09e2d55d4b247894987ceb1627c09caa66a7254129c77a1cbe92db3f6b6e6d5e6566b6e10876c03f44eb366f7fec62bca32c3d3f1bd550d3ee470bc23a5697e68ca6b0e0272e7a4073c1b1edd65a472ec90c19c52abeb1f323445d36c967cb3f1e7f7875135ba5c70b69a1c45a0d4ef92452890ded13cabb8a0264fb421bba9f894c6cb10350a4b012c3dd62a943d0fddab1cd3dabcb7b29d2582f653df4ae4011fca88d42bcdf4dee2d85dc9ea7fbe1c69d14b54dacca9f8be982167a875f0ba24b3a9af05ae75acfcc6cf13257c88889e1a384400150d040a24b41f6d9447fcebd800fdbebc4d3ea1332167531ce062b93b3d16cc4
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a0080a014ac.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49022);
 script_version("1.16");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");
 script_cve_id("CVE-2008-3804");
 script_bugtraq_id(31360);
 script_osvdb_id(48741);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsk93241");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20080924-mfi");
 script_name(english:"Cisco IOS MPLS Forwarding Infrastructure Denial of Service Vulnerability - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'Cisco IOS Software Multi Protocol Label Switching (MPLS) Forwarding
Infrastructure (MFI) is vulnerable to a denial of service (DoS) attack
from specially crafted packets. Only the MFI is affected by this
vulnerability. Older Label Forwarding Information Base (LFIB)
implementation, which is replaced by MFI, is not affected.

 Cisco has released free software updates that address this
vulnerability.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f9f25a71");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a0080a014ac.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?3530bda4");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20080924-mfi.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/09/24");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/09/24");
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

if (version == '12.4(15)XZ') flag++;
else if (version == '12.4(15)XY3') flag++;
else if (version == '12.4(15)XY2') flag++;
else if (version == '12.4(15)XY1') flag++;
else if (version == '12.4(15)XY') flag++;
else if (version == '12.4(15)XR') flag++;
else if (version == '12.4(15)XQ') flag++;
else if (version == '12.2(28)ZX') flag++;
else if (version == '12.2(33)XN1') flag++;
else if (version == '12.2(33)SXH2a') flag++;
else if (version == '12.2(33)SXH2') flag++;
else if (version == '12.2(33)SXH1') flag++;
else if (version == '12.2(33)SXH') flag++;
else if (version == '12.2(25)SW3a') flag++;
else if (version == '12.2(25)SW11') flag++;
else if (version == '12.2(29)SVE0') flag++;
else if (version == '12.2(29)SVD1') flag++;
else if (version == '12.2(29)SVD0') flag++;
else if (version == '12.2(29)SVD') flag++;
else if (version == '12.2(29)SVC') flag++;
else if (version == '12.2(29)SVA2') flag++;
else if (version == '12.2(29b)SV1') flag++;
else if (version == '12.2(29b)SV') flag++;
else if (version == '12.2(29a)SV1') flag++;
else if (version == '12.2(29a)SV') flag++;
else if (version == '12.2(29)SV3') flag++;
else if (version == '12.2(28)SV2') flag++;
else if (version == '12.2(28)SV1') flag++;
else if (version == '12.2(28)SV') flag++;
else if (version == '12.2(27)SV5') flag++;
else if (version == '12.2(27)SV4') flag++;
else if (version == '12.2(27)SV3') flag++;
else if (version == '12.2(27)SV2') flag++;
else if (version == '12.2(27)SV1') flag++;
else if (version == '12.2(27)SV') flag++;
else if (version == '12.2(25)SV2') flag++;
else if (version == '12.2(24)SV1') flag++;
else if (version == '12.2(23)SV1') flag++;
else if (version == '12.2(22)SV1') flag++;
else if (version == '12.2(33)SRC') flag++;
else if (version == '12.2(33)SRB3') flag++;
else if (version == '12.2(33)SRB2') flag++;
else if (version == '12.2(33)SRB1') flag++;
else if (version == '12.2(33)SRB') flag++;
else if (version == '12.2(33)SRA7') flag++;
else if (version == '12.2(33)SRA6') flag++;
else if (version == '12.2(33)SRA5') flag++;
else if (version == '12.2(33)SRA4') flag++;
else if (version == '12.2(33)SRA3') flag++;
else if (version == '12.2(33)SRA2') flag++;
else if (version == '12.2(33)SRA1') flag++;
else if (version == '12.2(33)SRA') flag++;
else if (version == '12.2(37)SG1') flag++;
else if (version == '12.2(31)SG2') flag++;
else if (version == '12.2(25)SEG3') flag++;
else if (version == '12.2(25)SEG1') flag++;
else if (version == '12.2(25)SEG') flag++;
else if (version == '12.2(25)SEE4') flag++;
else if (version == '12.2(25)SEE') flag++;
else if (version == '12.2(25)SED1') flag++;
else if (version == '12.2(25)SED') flag++;
else if (version == '12.2(44)SE2') flag++;
else if (version == '12.2(44)SE1') flag++;
else if (version == '12.2(44)SE') flag++;
else if (version == '12.2(40)SE') flag++;
else if (version == '12.2(37)SE1') flag++;
else if (version == '12.2(37)SE') flag++;
else if (version == '12.2(35)SE5') flag++;
else if (version == '12.2(35)SE2') flag++;
else if (version == '12.2(35)SE1') flag++;
else if (version == '12.2(33)SCA') flag++;
else if (version == '12.2(27)SBC5') flag++;
else if (version == '12.2(27)SBC4') flag++;
else if (version == '12.2(27)SBC3') flag++;
else if (version == '12.2(27)SBC2') flag++;
else if (version == '12.2(27)SBC1') flag++;
else if (version == '12.2(27)SBC') flag++;
else if (version == '12.2(27)SBB4e') flag++;
else if (version == '12.2(31)SB9') flag++;
else if (version == '12.2(31)SB8') flag++;
else if (version == '12.2(31)SB7') flag++;
else if (version == '12.2(31)SB6') flag++;
else if (version == '12.2(31)SB5') flag++;
else if (version == '12.2(31)SB3x') flag++;
else if (version == '12.2(31)SB3') flag++;
else if (version == '12.2(31)SB2') flag++;
else if (version == '12.2(31)SB11') flag++;
else if (version == '12.2(31)SB10') flag++;
else if (version == '12.2(28)SB9') flag++;
else if (version == '12.2(28)SB8') flag++;
else if (version == '12.2(28)SB7') flag++;
else if (version == '12.2(28)SB6') flag++;
else if (version == '12.2(28)SB5c') flag++;
else if (version == '12.2(28)SB5') flag++;
else if (version == '12.2(28)SB4d') flag++;
else if (version == '12.2(28)SB4') flag++;
else if (version == '12.2(28)SB3') flag++;
else if (version == '12.2(28)SB2') flag++;
else if (version == '12.2(28)SB12') flag++;
else if (version == '12.2(28)SB11') flag++;
else if (version == '12.2(28)SB10') flag++;
else if (version == '12.2(28)SB1') flag++;
else if (version == '12.2(28)SB') flag++;
else if (version == '12.2(25)S9') flag++;
else if (version == '12.2(25)S8') flag++;
else if (version == '12.2(25)S7') flag++;
else if (version == '12.2(25)S6') flag++;
else if (version == '12.2(25)S5') flag++;
else if (version == '12.2(25)S4') flag++;
else if (version == '12.2(25)S3') flag++;
else if (version == '12.2(25)S2') flag++;
else if (version == '12.2(25)S15') flag++;
else if (version == '12.2(25)S14') flag++;
else if (version == '12.2(25)S13') flag++;
else if (version == '12.2(25)S12') flag++;
else if (version == '12.2(25)S11') flag++;
else if (version == '12.2(25)S10') flag++;
else if (version == '12.2(25)S1') flag++;
else if (version == '12.2(25)S') flag++;
else if (version == '12.2(22)S2') flag++;
else if (version == '12.2(22)S1') flag++;
else if (version == '12.2(22)S') flag++;
else if (version == '12.2(33)IRA') flag++;
else if (version == '12.2(25)EY4') flag++;
else if (version == '12.2(25)EY3') flag++;
else if (version == '12.2(25)EY2') flag++;
else if (version == '12.2(25)EY1') flag++;
else if (version == '12.2(25)EY') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_subsys_name_mfi_ios", "show subsys name mfi_ios");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"mfi_ios\s+Protocol", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_mpls_interface", "show mpls interface");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"Interface", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
