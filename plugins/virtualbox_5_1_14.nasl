#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96609);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/04/21 16:53:28 $");

  script_cve_id(
    "CVE-2016-5545",
    "CVE-2017-3290",
    "CVE-2017-3316",
    "CVE-2017-3332"
  );
  script_bugtraq_id(
    95579,
    95590,
    95599,
    95601
  );
  script_osvdb_id(
    150437,
    150438,
    150439,
    150440
  );
  script_name(english:"Oracle VM VirtualBox 5.0.x < 5.0.32 / 5.1.x < 5.1.14 Multiple Vulnerabilities (January 2017 CPU)");
  script_summary(english:"Performs a version check on VirtualBox.exe.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle VM VirtualBox installed on the remote host is
5.0.x prior to 5.0.32 or 5.1.x prior to 5.1.14. It is, therefore,
affected by multiple vulnerabilities :

  - An unspecified flaw exists in the GUI subcomponent that
    allows an unauthenticated, remote attacker to impact
    confidentiality, integrity, and availability.
    (CVE-2016-5545)

  - An unspecified flaw exists in the Shared Folder
    subcomponent that allows a local attacker to impact
    integrity and availability. (CVE-2017-3290)

  - An unspecified flaw exists in the GUI subcomponent that
    allows an authenticated, remote attacker to execute
    arbitrary code. (CVE-2017-3316)

  - An unspecified flaw exists in the VirtualBox SVGA
    Emulation subcomponent that allows a local attacker to
    impact integrity and availability. (CVE-2017-3332)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?89a8e429");
  script_set_attribute(attribute:"see_also", value:"https://www.virtualbox.org/wiki/Changelog");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle VM VirtualBox version 5.0.32 / 5.1.14 or later as
referenced in the January 2017 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("virtualbox_installed.nasl", "macosx_virtualbox_installed.nbin");
  script_require_ports("installed_sw/Oracle VM VirtualBox", "installed_sw/VirtualBox");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app  = NULL;
apps = make_list('Oracle VM VirtualBox', 'VirtualBox');

foreach app (apps)
{
  if (get_install_count(app_name:app)) break;
  else app = NULL;
}

if (isnull(app)) audit(AUDIT_NOT_INST, 'Oracle VM VirtualBox');

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

ver  = install['version'];
path = install['path'];

# Affected :
# 5.0.x < 5.0.32 / 5.1.x < 5.1.14
if  (ver =~ '^5\\.0' && ver_compare(ver:ver, fix:'5.0.32', strict:FALSE) < 0) fix = '5.0.32';
else if  (ver =~ '^5\\.1' && ver_compare(ver:ver, fix:'5.1.14', strict:FALSE) < 0) fix = '5.1.14';
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);

port = 0;
if (app == 'Oracle VM VirtualBox')
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;
}

report =
  '\n  Path              : ' + path +
  '\n  Installed version : ' + ver +
  '\n  Fixed version     : ' + fix +
  '\n';
security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
exit(0);
