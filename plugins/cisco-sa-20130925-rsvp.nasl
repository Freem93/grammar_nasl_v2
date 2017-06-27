#TRUSTED 89046a517b266bc07e1c4f7d5b557540bb8363f6fa448d97627c5c322f0ef34de04ce9f2e3fa72c220d60df2318a98d861c3a2b0ca58dadd9d8f85d596a11349d9c6efe8d05677e59e2f852174436a227d9924980ebacac0f599756574365dad67fa7f979162687b98e94e1625145be58d2e10ed5a64b2ce774e2e1503a6d60f745b7adb11459ff0401812fc9b20aa91a7ecfc4b5c7bfdbf51e7592f5e77afc410093bc550a663b514c11ae63362e4f88794e1919c92d1aeca2235c1ba2bedefc0f49047d5206319d8cfa2bbd9161e87d832831434e4cbbf5ff17c1057abbbd31366d63cce729245d70e023203d15dc61a1ac51e095034e2abae6a6b49827034df7184cd3fad658b703b8a143a1ae7e207b7ec029dadefe79ffbfc5a999353a08e29728b879fd529b0ece3c39883e6aca15af6e2008f0c922add2be6bdafa35894d8e1ca4739560b9c1bda1606c77cc083ec80c34691cf129074214c1634202712a50469474efa2bd9ba54bf971afec15f18fb4d2c2111a2e7147d1bab27c1e1a501984a9e33c43005b01bc6ada524178763573f6153edf9f7dffaf335b952b447d895245727f5733c427ae6d522a20efd477baeef707d4fe82ded37a336313af106ffc14e0068a18971097bcd8a75b82d47b6c5d209207fc9de9d673d292f82c7121383e21911770cd7bb8fd563feb87d844a727ee6873f71beb2f5125f4a6b
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130925-rsvp.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(70313);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/04/01");

  script_cve_id("CVE-2013-5478");
  script_bugtraq_id(62646);
  script_osvdb_id(97735);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuf17023");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130925-rsvp");

  script_name(english:"Cisco IOS Software Resource Reservation Protocol Interface Queue Wedge Vulnerability (cisco-sa-20130925-rsvp)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote device is affected by a denial of service vulnerability due
to improper handling of UDP RSVP packets in the Resource Reservation
Protocol (RSVP) feature. An unauthenticated, remote attacker, via
specially-crafted UDP RSVP packets sent to port 1698, can trigger an
interface queue wedge, resulting in a loss of connectivity, loss of
routing protocol adjacency, and other denial of service conditions.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130925-rsvp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a057824");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130925-rsvp. Alternatively, apply the workaround referenced
in the advisory.");

  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
if ( version == '15.0(1)M' ) flag++;
if ( version == '15.0(1)M1' ) flag++;
if ( version == '15.0(1)M10' ) flag++;
if ( version == '15.0(1)M2' ) flag++;
if ( version == '15.0(1)M3' ) flag++;
if ( version == '15.0(1)M4' ) flag++;
if ( version == '15.0(1)M5' ) flag++;
if ( version == '15.0(1)M6' ) flag++;
if ( version == '15.0(1)M6a' ) flag++;
if ( version == '15.0(1)M7' ) flag++;
if ( version == '15.0(1)M8' ) flag++;
if ( version == '15.0(1)M9' ) flag++;
if ( version == '15.0(1)SY' ) flag++;
if ( version == '15.0(1)SY1' ) flag++;
if ( version == '15.0(1)SY2' ) flag++;
if ( version == '15.0(1)SY3' ) flag++;
if ( version == '15.0(1)SY4' ) flag++;
if ( version == '15.0(1)XA' ) flag++;
if ( version == '15.0(1)XA1' ) flag++;
if ( version == '15.0(1)XA2' ) flag++;
if ( version == '15.0(1)XA3' ) flag++;
if ( version == '15.0(1)XA4' ) flag++;
if ( version == '15.0(1)XA5' ) flag++;
if ( version == '15.1(1)MR' ) flag++;
if ( version == '15.1(1)MR1' ) flag++;
if ( version == '15.1(1)MR2' ) flag++;
if ( version == '15.1(1)MR3' ) flag++;
if ( version == '15.1(1)MR4' ) flag++;
if ( version == '15.1(1)MR5' ) flag++;
if ( version == '15.1(1)MR6' ) flag++;
if ( version == '15.1(1)S' ) flag++;
if ( version == '15.1(1)S1' ) flag++;
if ( version == '15.1(1)S2' ) flag++;
if ( version == '15.1(1)SA' ) flag++;
if ( version == '15.1(1)SA1' ) flag++;
if ( version == '15.1(1)SA2' ) flag++;
if ( version == '15.1(1)SY' ) flag++;
if ( version == '15.1(1)SY1' ) flag++;
if ( version == '15.1(1)T' ) flag++;
if ( version == '15.1(1)T1' ) flag++;
if ( version == '15.1(1)T2' ) flag++;
if ( version == '15.1(1)T3' ) flag++;
if ( version == '15.1(1)T4' ) flag++;
if ( version == '15.1(1)T5' ) flag++;
if ( version == '15.1(1)XB' ) flag++;
if ( version == '15.1(1)XB1' ) flag++;
if ( version == '15.1(2)EY' ) flag++;
if ( version == '15.1(2)EY1' ) flag++;
if ( version == '15.1(2)EY1a' ) flag++;
if ( version == '15.1(2)EY2' ) flag++;
if ( version == '15.1(2)EY2a' ) flag++;
if ( version == '15.1(2)EY3' ) flag++;
if ( version == '15.1(2)EY4' ) flag++;
if ( version == '15.1(2)GC' ) flag++;
if ( version == '15.1(2)GC1' ) flag++;
if ( version == '15.1(2)GC2' ) flag++;
if ( version == '15.1(2)S' ) flag++;
if ( version == '15.1(2)S1' ) flag++;
if ( version == '15.1(2)S2' ) flag++;
if ( version == '15.1(2)SNG' ) flag++;
if ( version == '15.1(2)SNH' ) flag++;
if ( version == '15.1(2)SNH1' ) flag++;
if ( version == '15.1(2)SNI' ) flag++;
if ( version == '15.1(2)SNI1' ) flag++;
if ( version == '15.1(2)T' ) flag++;
if ( version == '15.1(2)T0a' ) flag++;
if ( version == '15.1(2)T1' ) flag++;
if ( version == '15.1(2)T2' ) flag++;
if ( version == '15.1(2)T2a' ) flag++;
if ( version == '15.1(2)T3' ) flag++;
if ( version == '15.1(2)T4' ) flag++;
if ( version == '15.1(2)T5' ) flag++;
if ( version == '15.1(3)MR' ) flag++;
if ( version == '15.1(3)MRA' ) flag++;
if ( version == '15.1(3)MRA1' ) flag++;
if ( version == '15.1(3)S' ) flag++;
if ( version == '15.1(3)S0a' ) flag++;
if ( version == '15.1(3)S1' ) flag++;
if ( version == '15.1(3)S2' ) flag++;
if ( version == '15.1(3)S3' ) flag++;
if ( version == '15.1(3)S4' ) flag++;
if ( version == '15.1(3)S5' ) flag++;
if ( version == '15.1(3)S5a' ) flag++;
if ( version == '15.1(3)T' ) flag++;
if ( version == '15.1(3)T1' ) flag++;
if ( version == '15.1(3)T2' ) flag++;
if ( version == '15.1(3)T3' ) flag++;
if ( version == '15.1(3)T4' ) flag++;
if ( version == '15.1(4)GC' ) flag++;
if ( version == '15.1(4)GC1' ) flag++;
if ( version == '15.1(4)M' ) flag++;
if ( version == '15.1(4)M0a' ) flag++;
if ( version == '15.1(4)M0b' ) flag++;
if ( version == '15.1(4)M1' ) flag++;
if ( version == '15.1(4)M2' ) flag++;
if ( version == '15.1(4)M3' ) flag++;
if ( version == '15.1(4)M3a' ) flag++;
if ( version == '15.1(4)M4' ) flag++;
if ( version == '15.1(4)M5' ) flag++;
if ( version == '15.1(4)M6' ) flag++;
if ( version == '15.1(4)XB8a' ) flag++;
if ( version == '15.2(1)GC' ) flag++;
if ( version == '15.2(1)GC1' ) flag++;
if ( version == '15.2(1)GC2' ) flag++;
if ( version == '15.2(1)S' ) flag++;
if ( version == '15.2(1)S1' ) flag++;
if ( version == '15.2(1)S2' ) flag++;
if ( version == '15.2(1)SA' ) flag++;
if ( version == '15.2(1)SB' ) flag++;
if ( version == '15.2(1)SB1' ) flag++;
if ( version == '15.2(1)SB3' ) flag++;
if ( version == '15.2(1)SB4' ) flag++;
if ( version == '15.2(1)SC1a' ) flag++;
if ( version == '15.2(1)SC2' ) flag++;
if ( version == '15.2(1)T' ) flag++;
if ( version == '15.2(1)T1' ) flag++;
if ( version == '15.2(1)T2' ) flag++;
if ( version == '15.2(1)T3' ) flag++;
if ( version == '15.2(1)T3a' ) flag++;
if ( version == '15.2(1)T4' ) flag++;
if ( version == '15.2(2)GC' ) flag++;
if ( version == '15.2(2)S' ) flag++;
if ( version == '15.2(2)S0a' ) flag++;
if ( version == '15.2(2)S0c' ) flag++;
if ( version == '15.2(2)S0d' ) flag++;
if ( version == '15.2(2)S1' ) flag++;
if ( version == '15.2(2)S2' ) flag++;
if ( version == '15.2(2)SNG' ) flag++;
if ( version == '15.2(2)SNH' ) flag++;
if ( version == '15.2(2)SNH1' ) flag++;
if ( version == '15.2(2)SNI' ) flag++;
if ( version == '15.2(2)T' ) flag++;
if ( version == '15.2(2)T1' ) flag++;
if ( version == '15.2(2)T2' ) flag++;
if ( version == '15.2(2)T3' ) flag++;
if ( version == '15.2(3)GC' ) flag++;
if ( version == '15.2(3)GC1' ) flag++;
if ( version == '15.2(3)GCA' ) flag++;
if ( version == '15.2(3)T' ) flag++;
if ( version == '15.2(3)T1' ) flag++;
if ( version == '15.2(3)T2' ) flag++;
if ( version == '15.2(3)T3' ) flag++;
if ( version == '15.2(3)XA' ) flag++;
if ( version == '15.2(4)M' ) flag++;
if ( version == '15.2(4)M1' ) flag++;
if ( version == '15.2(4)M2' ) flag++;
if ( version == '15.2(4)M3' ) flag++;
if ( version == '15.2(4)S' ) flag++;
if ( version == '15.2(4)S0c' ) flag++;
if ( version == '15.2(4)S1' ) flag++;
if ( version == '15.2(4)S2' ) flag++;
if ( version == '15.2(4)S3' ) flag++;
if ( version == '15.2(4)S3a' ) flag++;
if ( version == '15.2(4)XB10' ) flag++;
if ( version == '15.3(1)S' ) flag++;
if ( version == '15.3(1)S1' ) flag++;
if ( version == '15.3(1)S1e' ) flag++;
if ( version == '15.3(1)S2' ) flag++;
if ( version == '15.3(1)T' ) flag++;
if ( version == '15.3(1)T1' ) flag++;
if ( version == '15.3(2)T' ) flag++;

if (get_kb_item("Host/local_checks_enabled") && flag)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_rsvp", "show ip rsvp");
  if (check_cisco_result(buf))
  {
    if ("RSVP: enabled" >< buf) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug IDs     : CSCuf17023' +
      '\n  Installed release : ' + version +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
  }
  else security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
