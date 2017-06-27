#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77689);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/03 17:40:02 $");

  script_cve_id("CVE-2014-3820");
  script_bugtraq_id(69801);
  script_xref(name:"IAVA", value:"2014-A-0137");
  script_xref(name:"IAVA", value:"2014-A-0138");

  script_name(english:"Junos Pulse Secure Access IVE / UAC OS XSS (JSA10645)");
  script_summary(english:"Checks IVE/UAC OS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of IVE / UAC OS
running on the remote host is affected by a cross site scripting
vulnerability due to incorrect user input validation on the SSL VPN /
UAC web server. Note that this issue exists within a web page that is
only accessible by an authenticated administrator session.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10645");

  script_set_attribute(attribute:"solution", value:
"Upgrade to Juniper Junos IVE OS version 7.1r18 / 7.3r10 / 7.4r8 /
8.0r1 or later or UAC OS version 4.1r8 / 4.4r8 / 5.0r1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:ive_os");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_pulse_secure_access_service");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_pulse_access_control_service");

  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Juniper/IVE OS/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit('Host/Juniper/IVE OS/Version');
match = eregmatch(string:version, pattern:"^([0-9.]+)[Rr]([0-9.]+)");
if (isnull(match)) exit(1, 'Error parsing version: ' + version);

release = match[1];
build   = match[2];

# IVE OS
if (release == '7.1' && ver_compare(ver:build, fix:'18', strict:FALSE) == -1)
  fix = '7.1r18';
else if (release == '7.3' && ver_compare(ver:build, fix:'10', strict:FALSE) == -1)
  fix = '7.3r10';
else if (release == '7.4' && ver_compare(ver:build, fix:'8', strict:FALSE) == -1)
  fix = '7.4r8';
else if (release == '8.0' && ver_compare(ver:build, fix:'1', strict:FALSE) == -1)
  fix = '8.0r1';
# UAC OS
else if (release == '4.1' && ver_compare(ver:build, fix:'8', strict:FALSE) == -1)
  fix = '4.1r8';
else if (release == '4.4' && ver_compare(ver:build, fix:'8', strict:FALSE) == -1)
  fix = '4.4r8';
else if (release == '5.0' && ver_compare(ver:build, fix:'1', strict:FALSE) == -1)
  fix = '5.0r1';
# Not affected
else
  audit(AUDIT_INST_VER_NOT_VULN, 'IVE/UAC OS', version);

set_kb_item(name:"www/0/XSS",value:TRUE);
if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix + '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
