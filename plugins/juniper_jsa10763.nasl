#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94332);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/05/01 17:16:44 $");

  script_cve_id("CVE-2016-4922");
  script_bugtraq_id(93534);
  script_osvdb_id(145589);
  script_xref(name:"JSA", value:"JSA10763");

  script_name(english:"Juniper Junos Multiple CLI Command Handling Local Privilege Escalations (JSA10763)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by multiple privilege escalation
vulnerabilities in the Junos CLI. A local attacker can exploit these,
via specially crafted CLI commands and arguments, to gain elevated
privileges.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10763");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
advisory JSA10763.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

fixes['12.1X46'] = '12.1X46-D60';
fixes['12.1X47'] = '12.1X47-D45';
fixes['12.3X48'] = '12.3X48-D35';
fixes['12.3'] = '12.3R12';
fixes['13.2'] = '13.2R9';
fixes['13.3'] = '13.3R9';
fixes['14.1'] = '14.1R7';
fixes['14.1X53'] = '14.1X53-D40';
fixes['14.1X55'] = '14.1X55-D35';
fixes['14.2'] = '14.2R5';
fixes['15.1F'] = '15.1F4';
fixes['15.1R'] = '15.1R3';
fixes['15.1X49'] = '15.1X49-D60';
fixes['15.1X53'] = '15.1X53-D70';
fixes['16.1R'] = '16.1R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

junos_report(ver:ver, fix:fix, model:model, severity:SECURITY_HOLE);
