#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89784);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/09 15:19:41 $");

  script_cve_id("CVE-2015-0718");
  script_bugtraq_id(83950);
  script_osvdb_id(135231);
  script_xref(name:"CISCO-BUG-ID", value:"CSCub70579");
  script_xref(name:"CISCO-BUG-ID", value:"CSCue79544");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo58749");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup97337");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup97345");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup97366");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160302-netstack");

  script_name(english:"Cisco Nexus TCP Packet TIME_WAIT State Handling DoS (cisco-sa-20160302-netstack)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Nexus device is affected by a denial of service
vulnerability due to improper processing of certain TCP packets in the
closing sequence of a TCP session while the affected device is in a
TIME_WAIT state. An unauthenticated, remote attacker can exploit this
vulnerability, by sending a crafted sequence of TCP packets when the
device is in a TIME_WAIT state, to cause a reload of the TCP stack,
resulting in a denial of service condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160302-netstack
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?378ab6f5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the Cisco bug ID
for your model.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/09");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

device  = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model   = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");
version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");
flag    = 0;
fix     = FALSE;
bug     = FALSE;

if (model == "1000V")
{
  fix = "5.2(1)SV3(1.1)";
  bug = "CSCup97366";
}
else if (model =~ "^3[0-4][0-9][0-9][0-9]?([^0-9]|$)")
{
  fix = "6.0(2)U1(1)";
  bug = "CSCue79544";
}
else if (model =~ "^35[0-9][0-9]([^0-9]|$)")
{
  fix = "6.0(2)A1(1)";
  bug = "CSCue79544";
}
else if (model =~ "^40[0-9][0-9]([^0-9]|$)" && version =~ "^4\.1([^0-9])")
{
  fix = "4.1(2)E1(1n)";
  bug = "CSCup97337";
}
else if (model =~ "^[5-6][0-9][0-9][0-9]([^0-9]|$)")
{
  # Fixes for multiple trains
  if (version =~ "^[1-4]\." || version =~ "^5\.[1-2]([^0-9])")
    fix = "5.2(1)N1(9)";
  else if (version =~ "^6\.0([^0-9])")
    fix = "6.0(2)N2(7)";
  else if (version =~ "^7\.0([^0-9])")
    fix = "7.0(0)N1(1)";
  bug = "CSCup97345";
}
else if (model =~ "^7[07][0-9][0-9]([^0-9]|$)")
{
  # Fixes for multiple trains
  if (version =~ "^[1-4]\." || version =~ "^5\.[1-2]([^0-9])")
    fix = "5.2(9)";
  else if (version =~ "^6\.[0-1]([^0-9])")
    fix = "6.1(4a)";
  else if (version =~ "^6\.2([^0-9])")
    fix = "6.2(2)";
  bug = "CSCub70579";
}

# if we are actully a UCS device we just need to check it's version
if ("Cisco UCS" >< device)
{
  # Prior to 2.2(2c) are all affected.
  if (version =~ "^1\." || version =~ "^2\.[012]([^0-9])")
  {
    fix = "2.2(2c)";
    bug = "CSCuo58749";
  }
  else
    fix = FALSE;
}

if (!fix)
  audit(AUDIT_HOST_NOT, "affected");

if (cisco_gen_ver_compare(a:version, b:fix) == -1)
  flag += 1;

if (flag)
{
  report =
    '\n  Model             : ' + device + ' ' + model +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n  Cisco bug ID      : ' + bug;
  security_report_v4(port:0, extra:report+'\n', severity:SECURITY_HOLE);
}
else audit(AUDIT_HOST_NOT, "affected");
