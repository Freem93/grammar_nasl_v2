#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94331);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/01/23 17:47:51 $");

  script_cve_id("CVE-2016-4922");
  script_bugtraq_id(93534);
  script_osvdb_id(145587);
  script_xref(name:"JSA", value:"JSA10762");

  script_name(english:"Juniper Junos IPv6 Packet Handling Remote DoS (JSA10762)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Juniper Junos device is affected by a denial of service
vulnerability in the IPV6 implementation. An unauthenticated, remote
attacker can exploit this, via a flood of specially crafted IPv6
traffic, to exhaust available resources or cause a kernel panic.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10762");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
advisory JSA10762.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

fixes['11.4'] = '11.4R13'; # or 11.4R13-S3
fixes['12.1X44'] = '12.1X44-D45';
fixes['12.1X46'] = '12.1X46-D30';
fixes['12.1X47'] = '12.1X47-D20';
fixes['12.3'] = '12.3R9';
fixes['13.3'] = '13.3R5'; # or 13.3R10
fixes['12.3X48'] = '12.3X48-D30';
fixes['14.1'] = '14.1R8';
fixes['14.1X53'] = '14.1X53-D28'; # or 14.1X53-D40
fixes['14.1X55'] = '14.1X55-D35';
fixes['14.2'] = '14.2R6';
fixes['15.1R'] = '15.1R3';
fixes['15.1F'] = '15.1F5-S2'; # or 15.1F6
fixes['15.1X49'] = '15.1X49-D40';
fixes['15.1X53'] = '15.1X53-D61'; # or 15.1X53-D70
fixes['16.1R'] = '16.1R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (fix == "11.4R13")
  fix += " or 11.4R13-S3";
if (fix == "13.3R5")
  fix += " or 13.3R10";
if (fix == "14.1X53-D28")
  fix += " or 14.1X53-D40";
if (fix == "15.1F5-S2")
  fix += " or 15.1F6";
if (fix == "15.1X53-D61")
  fix += " or 15.1X53-D70";

override = TRUE;
buf = junos_command_kb_item(cmd:"show interfaces");
if (buf)
{
  pattern = "(inet6)";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because IPv6 traffic is not enabled.');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
