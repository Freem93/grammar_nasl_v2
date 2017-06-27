#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88052);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/02 15:47:18 $");

  script_cve_id(
    "CVE-2016-0495",
    "CVE-2016-0592",
    "CVE-2016-0602"
  );
  script_osvdb_id(
    133375,
    133376,
    133377
  );

  script_name(english:"Oracle VM VirtualBox < 4.3.36 / 5.0.14 Multiple Vulnerabilities (January 2016 CPU)");
  script_summary(english:"Performs a version check on VirtualBox.exe.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Oracle VM VirtualBox application installed on the remote host is a
version prior to 4.3.36 or 5.0.14. It is, therefore, affected by the
following vulnerabilities :

  - An unspecified vulnerability exists in the Core
    subcomponent that allows a remote attacker to affect the
    availability of the system. No other details are
    available. (CVE-2016-0495)

  - An unspecified vulnerability exists in the Core
    subcomponent that allows a local attacker to affect the
    availability of the system. No other details are
    available. (CVE-2016-0592)

  - An unspecified vulnerability exists in the Windows
    Installer subcomponent that allows a local attacker
    to gain elevated privileges. No other details are
    available. (CVE-2016-0602)");
  # http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html#AppendixOVIR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c48cc983");
  script_set_attribute(attribute:"see_also", value:"https://www.virtualbox.org/wiki/Changelog");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle VM VirtualBox version 4.3.36 / 5.0.14 or later as
referenced in the January 2016 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

# Note int(null) returns '0'
ver_fields = split(ver, sep:'.', keep:FALSE);
major = int(ver_fields[0]);
minor = int(ver_fields[1]);
rev   = int(ver_fields[2]);

fix = '';

# Affected :
# 4.3.x < 4.3.36
# 5.0.x < 5.0.14
if (major == 4 && minor == 3 && rev < 36) fix = '4.3.36';
else if (major == 5 && minor == 0 && rev < 14)  fix = '5.0.14';
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);

port = 0;
if (app == 'Oracle VM VirtualBox')
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;
}

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
