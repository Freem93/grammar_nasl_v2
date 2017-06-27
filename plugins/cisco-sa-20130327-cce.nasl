#TRUSTED 577d5301e399aa4048f43e4fea5c4c84937fc54c7051d33524008ef19c4eb15b327674fff1149655d50bcf70b526644ba5d6f15a63b7b68bfb33639d4a706d1f2508843f2bdf843da3a16a8f5c6f7719d753c8a771afc61ad876d2e9002f552eae1fcc1d3617f815ac06f931725b3967b1f91131462845be19ad6dad65842c8f712b61084b2f4a59b71434ff4dd9640b9461895204d5d1c07765e321b01d5e2d74d93b00c58899627f0ecacc2cc70d5514073a5b470df04a03178e88c68523e61470d09e189a4d4ff1f0be2a0bc3a20049191055beaa3edfff9ac4f4aa6279391f8deeff7057e5191cd05cf40fe96cb8478617c76d5f4220a74f9622ac262d4ad99f012169ac7b448f35157f018155ebac9b11760c58fd64abb0a0ea7e277ca747d5198cd136e68add905937da5980187efc33138bd5657b0a0f33f8f70b5ffbfa4b05f2cc62589b3ebf41b6c72d6aecdbc3ed21bc08be8646519376e744e7f24f52c7eabac3fad3bd1eec2468f411b6ec39ba0f78a05bc42ed53d82c99ebe048c24b06965dd125957ba3a1bdb1b109fc88d1295a66ca99c8fa2baa4d891ced1df5f5390520c130057bd6c8dbb50420e452ae5fa32cc43decf0dc548c4e3d07ec0a7f3d3d8e96fd96c884951e6573aca8d2ecbdeb484c28a819b1cb243df6b6551071d97d8ee37d5af4f8e10f4c0d125c59d351edc0c68188bb7f33d54d206c1
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130327-cce.
# The text itself is copyright (C) Cisco
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(65885);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/03");

  script_cve_id("CVE-2013-1145");
  script_bugtraq_id(58741);
  script_osvdb_id(91759);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtl99174");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130327-cce");

  script_name(english:"Cisco IOS Software Zone-Based Policy Firewall Session Initiation Protocol Inspection Denial of Service Vulnerability (cisco-sa-20130327-cce)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Cisco IOS Software contains a memory leak vulnerability that could be
triggered through the processing of malformed Session Initiation
Protocol (SIP) messages. Exploitation of this vulnerability could
cause an interruption of services. Only devices that are configured
for SIP inspection are affected by this vulnerability. Cisco has
released free software updates that address this vulnerability. There
are no workarounds for devices that must run SIP inspection."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130327-cce
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3171f46f"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130327-cce."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/10");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if ( version == '12.4(15)XZ' ) flag++;
if ( version == '12.4(15)XZ1' ) flag++;
if ( version == '12.4(15)XZ2' ) flag++;
if ( version == '12.4(20)MR' ) flag++;
if ( version == '12.4(20)MR2' ) flag++;
if ( version == '12.4(20)MRA' ) flag++;
if ( version == '12.4(20)MRA1' ) flag++;
if ( version == '12.4(20)MRB' ) flag++;
if ( version == '12.4(20)MRB1' ) flag++;
if ( version == '12.4(20)T' ) flag++;
if ( version == '12.4(20)T1' ) flag++;
if ( version == '12.4(20)T2' ) flag++;
if ( version == '12.4(20)T3' ) flag++;
if ( version == '12.4(20)T4' ) flag++;
if ( version == '12.4(20)T5' ) flag++;
if ( version == '12.4(20)T5a' ) flag++;
if ( version == '12.4(20)T6' ) flag++;
if ( version == '12.4(20)YA' ) flag++;
if ( version == '12.4(20)YA1' ) flag++;
if ( version == '12.4(20)YA2' ) flag++;
if ( version == '12.4(20)YA3' ) flag++;
if ( version == '12.4(22)GC1' ) flag++;
if ( version == '12.4(22)GC1a' ) flag++;
if ( version == '12.4(22)MD' ) flag++;
if ( version == '12.4(22)MD1' ) flag++;
if ( version == '12.4(22)MD2' ) flag++;
if ( version == '12.4(22)MDA' ) flag++;
if ( version == '12.4(22)MDA1' ) flag++;
if ( version == '12.4(22)MDA2' ) flag++;
if ( version == '12.4(22)MDA3' ) flag++;
if ( version == '12.4(22)MDA4' ) flag++;
if ( version == '12.4(22)MDA5' ) flag++;
if ( version == '12.4(22)MDA6' ) flag++;
if ( version == '12.4(22)T' ) flag++;
if ( version == '12.4(22)T1' ) flag++;
if ( version == '12.4(22)T2' ) flag++;
if ( version == '12.4(22)T3' ) flag++;
if ( version == '12.4(22)T4' ) flag++;
if ( version == '12.4(22)T5' ) flag++;
if ( version == '12.4(22)XR' ) flag++;
if ( version == '12.4(22)XR1' ) flag++;
if ( version == '12.4(22)XR10' ) flag++;
if ( version == '12.4(22)XR11' ) flag++;
if ( version == '12.4(22)XR12' ) flag++;
if ( version == '12.4(22)XR2' ) flag++;
if ( version == '12.4(22)XR3' ) flag++;
if ( version == '12.4(22)XR4' ) flag++;
if ( version == '12.4(22)XR5' ) flag++;
if ( version == '12.4(22)XR6' ) flag++;
if ( version == '12.4(22)XR7' ) flag++;
if ( version == '12.4(22)XR8' ) flag++;
if ( version == '12.4(22)XR9' ) flag++;
if ( version == '12.4(22)YB' ) flag++;
if ( version == '12.4(22)YB1' ) flag++;
if ( version == '12.4(22)YB4' ) flag++;
if ( version == '12.4(22)YB5' ) flag++;
if ( version == '12.4(22)YB6' ) flag++;
if ( version == '12.4(22)YB7' ) flag++;
if ( version == '12.4(22)YB8' ) flag++;
if ( version == '12.4(22)YD' ) flag++;
if ( version == '12.4(22)YD1' ) flag++;
if ( version == '12.4(22)YD2' ) flag++;
if ( version == '12.4(22)YD3' ) flag++;
if ( version == '12.4(22)YD4' ) flag++;
if ( version == '12.4(22)YE' ) flag++;
if ( version == '12.4(22)YE1' ) flag++;
if ( version == '12.4(22)YE2' ) flag++;
if ( version == '12.4(22)YE3' ) flag++;
if ( version == '12.4(22)YE4' ) flag++;
if ( version == '12.4(22)YE5' ) flag++;
if ( version == '12.4(22)YE6' ) flag++;
if ( version == '12.4(24)GC1' ) flag++;
if ( version == '12.4(24)GC3' ) flag++;
if ( version == '12.4(24)GC3a' ) flag++;
if ( version == '12.4(24)GC4' ) flag++;
if ( version == '12.4(24)GC5' ) flag++;
if ( version == '12.4(24)MD' ) flag++;
if ( version == '12.4(24)MD1' ) flag++;
if ( version == '12.4(24)MD2' ) flag++;
if ( version == '12.4(24)MD3' ) flag++;
if ( version == '12.4(24)MD4' ) flag++;
if ( version == '12.4(24)MD5' ) flag++;
if ( version == '12.4(24)MD6' ) flag++;
if ( version == '12.4(24)MD7' ) flag++;
if ( version == '12.4(24)MDA' ) flag++;
if ( version == '12.4(24)MDA1' ) flag++;
if ( version == '12.4(24)MDA10' ) flag++;
if ( version == '12.4(24)MDA11' ) flag++;
if ( version == '12.4(24)MDA12' ) flag++;
if ( version == '12.4(24)MDA13' ) flag++;
if ( version == '12.4(24)MDA2' ) flag++;
if ( version == '12.4(24)MDA3' ) flag++;
if ( version == '12.4(24)MDA4' ) flag++;
if ( version == '12.4(24)MDA5' ) flag++;
if ( version == '12.4(24)MDA6' ) flag++;
if ( version == '12.4(24)MDA7' ) flag++;
if ( version == '12.4(24)MDA8' ) flag++;
if ( version == '12.4(24)MDA9' ) flag++;
if ( version == '12.4(24)MDB' ) flag++;
if ( version == '12.4(24)MDB1' ) flag++;
if ( version == '12.4(24)MDB10' ) flag++;
if ( version == '12.4(24)MDB11' ) flag++;
if ( version == '12.4(24)MDB12' ) flag++;
if ( version == '12.4(24)MDB3' ) flag++;
if ( version == '12.4(24)MDB4' ) flag++;
if ( version == '12.4(24)MDB5' ) flag++;
if ( version == '12.4(24)MDB5a' ) flag++;
if ( version == '12.4(24)MDB6' ) flag++;
if ( version == '12.4(24)MDB7' ) flag++;
if ( version == '12.4(24)MDB8' ) flag++;
if ( version == '12.4(24)MDB9' ) flag++;
if ( version == '12.4(24)MDC' ) flag++;
if ( version == '12.4(24)T' ) flag++;
if ( version == '12.4(24)T1' ) flag++;
if ( version == '12.4(24)T2' ) flag++;
if ( version == '12.4(24)T3' ) flag++;
if ( version == '12.4(24)T31f' ) flag++;
if ( version == '12.4(24)T32f' ) flag++;
if ( version == '12.4(24)T33f' ) flag++;
if ( version == '12.4(24)T34f' ) flag++;
if ( version == '12.4(24)T35c' ) flag++;
if ( version == '12.4(24)T35f' ) flag++;
if ( version == '12.4(24)T36f' ) flag++;
if ( version == '12.4(24)T3c' ) flag++;
if ( version == '12.4(24)T3e' ) flag++;
if ( version == '12.4(24)T3f' ) flag++;
if ( version == '12.4(24)T3g' ) flag++;
if ( version == '12.4(24)T4' ) flag++;
if ( version == '12.4(24)T4a' ) flag++;
if ( version == '12.4(24)T4b' ) flag++;
if ( version == '12.4(24)T4c' ) flag++;
if ( version == '12.4(24)T4d' ) flag++;
if ( version == '12.4(24)T4e' ) flag++;
if ( version == '12.4(24)T4f' ) flag++;
if ( version == '12.4(24)T4g' ) flag++;
if ( version == '12.4(24)T4h' ) flag++;
if ( version == '12.4(24)T4i' ) flag++;
if ( version == '12.4(24)T4j' ) flag++;
if ( version == '12.4(24)T5' ) flag++;
if ( version == '12.4(24)T6' ) flag++;
if ( version == '12.4(24)T7' ) flag++;
if ( version == '12.4(24)T8' ) flag++;
if ( version == '12.4(24)YE' ) flag++;
if ( version == '12.4(24)YE1' ) flag++;
if ( version == '12.4(24)YE2' ) flag++;
if ( version == '12.4(24)YE3' ) flag++;
if ( version == '12.4(24)YE3a' ) flag++;
if ( version == '12.4(24)YE3b' ) flag++;
if ( version == '12.4(24)YE3c' ) flag++;
if ( version == '12.4(24)YE3d' ) flag++;
if ( version == '12.4(24)YE4' ) flag++;
if ( version == '12.4(24)YE5' ) flag++;
if ( version == '12.4(24)YE6' ) flag++;
if ( version == '12.4(24)YE7' ) flag++;
if ( version == '12.4(24)YG1' ) flag++;
if ( version == '12.4(24)YG2' ) flag++;
if ( version == '12.4(24)YG3' ) flag++;
if ( version == '12.4(24)YG4' ) flag++;
if ( version == '15.0(1)M' ) flag++;
if ( version == '15.0(1)M1' ) flag++;
if ( version == '15.0(1)M2' ) flag++;
if ( version == '15.0(1)M3' ) flag++;
if ( version == '15.0(1)M4' ) flag++;
if ( version == '15.0(1)M5' ) flag++;
if ( version == '15.0(1)M6' ) flag++;
if ( version == '15.0(1)M6a' ) flag++;
if ( version == '15.0(1)M7' ) flag++;
if ( version == '15.0(1)M8' ) flag++;
if ( version == '15.0(1)M9' ) flag++;
if ( version == '15.0(1)XA' ) flag++;
if ( version == '15.0(1)XA1' ) flag++;
if ( version == '15.0(1)XA2' ) flag++;
if ( version == '15.0(1)XA3' ) flag++;
if ( version == '15.0(1)XA4' ) flag++;
if ( version == '15.0(1)XA5' ) flag++;
if ( version == '15.1(1)T' ) flag++;
if ( version == '15.1(1)T1' ) flag++;
if ( version == '15.1(1)T2' ) flag++;
if ( version == '15.1(1)T3' ) flag++;
if ( version == '15.1(1)T4' ) flag++;
if ( version == '15.1(1)T5' ) flag++;
if ( version == '15.1(1)XB' ) flag++;
if ( version == '15.1(1)XB1' ) flag++;
if ( version == '15.1(1)XB2' ) flag++;
if ( version == '15.1(1)XB3' ) flag++;
if ( version == '15.1(2)GC' ) flag++;
if ( version == '15.1(2)GC1' ) flag++;
if ( version == '15.1(2)GC2' ) flag++;
if ( version == '15.1(2)T' ) flag++;
if ( version == '15.1(2)T0a' ) flag++;
if ( version == '15.1(2)T1' ) flag++;
if ( version == '15.1(2)T2' ) flag++;
if ( version == '15.1(2)T2a' ) flag++;
if ( version == '15.1(2)T3' ) flag++;
if ( version == '15.1(2)T4' ) flag++;
if ( version == '15.1(2)T5' ) flag++;
if ( version == '15.1(3)T' ) flag++;
if ( version == '15.1(3)T1' ) flag++;
if ( version == '15.1(3)T2' ) flag++;
if ( version == '15.1(3)T3' ) flag++;
if ( version == '15.1(3)T4' ) flag++;
if ( version == '15.1(4)GC' ) flag++;
if ( version == '15.1(4)M' ) flag++;
if ( version == '15.1(4)M0a' ) flag++;
if ( version == '15.1(4)M0b' ) flag++;
if ( version == '15.1(4)M1' ) flag++;
if ( version == '15.1(4)M2' ) flag++;
if ( version == '15.1(4)M3' ) flag++;
if ( version == '15.1(4)M3a' ) flag++;
if ( version == '15.1(4)M4' ) flag++;
if ( version == '15.1(4)M5' ) flag++;
if ( version == '15.1(4)XB4' ) flag++;
if ( version == '15.1(4)XB5' ) flag++;
if ( version == '15.1(4)XB5a' ) flag++;
if ( version == '15.1(4)XB6' ) flag++;
if ( version == '15.1(4)XB7' ) flag++;
if ( version == '15.1(4)XB8a' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_policy-map_type_inspect_zone-pair", "show policy-map type inspect zone-pair");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"Match:\s+[Pp]rotocol sip", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
