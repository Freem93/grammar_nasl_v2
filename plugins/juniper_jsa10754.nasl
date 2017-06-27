#TRUSTED 2a98100bea0c70f267424df1badd48364505788c91b6194cf4711074317ff61729ce2ab59a9b250e8a60bc84fff0ea68bbb7c621a2811166f16e8d4937b6e3f95f78c3414ec300c4e4dc3ab01a1501258d2da89587b81bbfb6cf3d9b05cc2fabb85ff90491a137e4be26abbf6fd3f30924c39476bb25a3dd01a7e7467152ece35ecfdfe9527d4e90937108bc89601f917b8df32390719232e14ec4fe4633f936c1942ca3c5df05405d266d55fd555485077dc3c2ce5c685f5f7d28b09c14451b809991c0a7e6b85d77b3738e7cf544b789a665f6884f0fed766eeac6723e3312d0623705955c1d4656ff2e5db781c3251032c19db910f9cf62e8b3cfbe436fd486360ea9a89e00f7c4206e27d36fa5050f749e14798a6e8a20f19eed6e81c506abfa03eb8fc4247c666200cf2b1f16910e6f0894ac32b2911d692fe433205c78272ca6c403eb4684fc8b463a93733caf6484f2b2d1f247ff8ad3316a43a2a2247321805431638b13f361b6895a291683a28d74e4bb2a2f127b3cffec7af0ac941853fe425b8a554f9392fea2477e7df81ecbbc58c47458e9a633f19c6e8346c40c1cbad46ec2973365d067585c5076449a3c855c1b89c1cc56d0b14d0c64d799a0951ed25c7ab5a613e85f3e5b509379519f31af8d123449fc52febc28984a46b53bac87f8d14f3caaa2f44b7ccea01f91c898914bc9d6555e8e5198323c9b68
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92512);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/10/27");

  script_cve_id("CVE-2016-1279");
  script_bugtraq_id(91759);
  script_osvdb_id(141471);
  script_xref(name:"JSA", value:"JSA10754");

  script_name(english:"Juniper Junos J-Web Service Privilege Escalation (JSA10754)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Juniper Junos device is affected by a privilege escalation
vulnerability in the J-Web service that allows an unauthenticated,
remote attacker to disclose sensitive information and gain
administrative privileges.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10754");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
advisory JSA10754. Alternatively, disable the J-Web service.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

fixes['12.1X46'] = '12.1X46-D45'; # or 12.1X46-D46 or 12.1X46-D51
fixes['12.1X47'] = '12.1X47-D35';
fixes['12.3'] = '12.3R12';
fixes['12.3X48'] = '12.3X48-D25';
fixes['13.3'] = '13.3R9-S1'; # or 13.3R10
fixes['14.1'] = '14.1R7';
fixes['14.1X53'] = '14.1X53-D35';
fixes['14.2'] = '14.2R6';
fixes['15.1R'] = '15.1A2'; # 15.1R3
fixes['15.1F'] =  '15.1F4';
fixes['15.1X49'] = '15.1X49-D30';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (fix == "12.1X46-D45")
  fix += " or 12.1X46-D46 or 12.1X46-D51";
if (fix == "13.3R9-S1")
  fix += " or 13.3R10";
if (fix == "15.1A2")
  fix += " or 15.1R3";

override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set system services web-management";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because the web-management service is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
