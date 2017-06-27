#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99509);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/04/20 15:44:22 $");

  script_cve_id(
    "CVE-2017-3513",
    "CVE-2017-3538",
    "CVE-2017-3558",
    "CVE-2017-3559",
    "CVE-2017-3561",
    "CVE-2017-3563",
    "CVE-2017-3575",
    "CVE-2017-3576",
    "CVE-2017-3587"
  );
  script_bugtraq_id(
    97698,
    97730,
    97732,
    97736,
    97739,
    97744,
    97750,
    97755,
    97759
  );
  script_osvdb_id(
    153848,
    155855,
    155856,
    155857,
    155858,
    155859,
    155860,
    155861,
    155862
  );
  script_xref(name:"IAVA", value:"2017-A-0117");

  script_name(english:"Oracle VM VirtualBox 5.0.x < 5.0.38 / 5.1.x < 5.1.20 (April 2017 CPU)");
  script_summary(english:"Performs a version check on VirtualBox.exe");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The version of Oracle VM VirtualBox installed on the remote host is
5.0.x prior to 5.0.38 or 5.1.x prior to 5.1.20. It is, therefore,
affected by multiple vulnerabilities :

  - An unspecified flaw exists in the Core component that
    allows a local attacker to disclose potentially
    sensitive information. (CVE-2017-3513)

  - An flaw exists in the Shared Folder component,
    specifically when cooperating guests access files
    within a shared folder while moving it. A local attacker
    within a guest can exploit this to read arbitrary files
    on the host. (CVE-2017-3538)

  - Multiple unspecified flaws exist in the Core component
    that allow a local attacker to impact confidentiality,
    integrity, and availability. (CVE-2017-3558,
    CVE-2017-3559, CVE-2017-3561, CVE-2017-3563,
    CVE-2017-3576)

  - An unspecified flaw exists in the Core component that
    allows a local attacker to impact integrity and
    availability. (CVE-2017-3575)

  - An unspecified flaw exists in the Shared Folder
    component that allows a local attacker to impact
    integrity and availability. (CVE-2017-3587)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?623d2c22");
  script_set_attribute(attribute:"see_also", value:"https://www.virtualbox.org/wiki/Changelog");
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/3681811.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08e1362c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle VM VirtualBox version 5.0.38 / 5.1.20 or later as
referenced in the April 2017 Oracle Critical Patch Update advisory.

Note that vulnerability CVE-2017-3538 was fixed in versions 5.0.34 and
5.1.16.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
# 5.0.x < 5.0.38 / 5.1.x < 5.1.20
if      (ver =~ '^5\\.0' && ver_compare(ver:ver, fix:'5.0.38', strict:FALSE) < 0) fix = '5.0.38';
else if (ver =~ '^5\\.1' && ver_compare(ver:ver, fix:'5.1.20', strict:FALSE) < 0) fix = '5.1.20';
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
