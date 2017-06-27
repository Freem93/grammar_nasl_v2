#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78549);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/10/17 20:48:01 $");

  script_cve_id("CVE-2014-6540");
  script_bugtraq_id(70493);
  script_osvdb_id(113358);

  script_name(english:"Oracle VM VirtualBox < 4.1.34 / 4.2.26 / 4.3.14 WDDM DoS (October 2014 CPU)");
  script_summary(english:"Performs a version check on VirtualBox.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by denial of
service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of Oracle VM VirtualBox that is
prior to 4.1.34, 4.2.x prior to 4.2.26, or 4.3.x prior to 4.3.14. It
is, therefore, affected by a denial of service vulnerability in the
Windows guests graphic driver (WDDM).");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2014-1972960.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6dcc7b47");
  script_set_attribute(attribute:"see_also", value:"https://www.virtualbox.org/wiki/Changelog");
  script_set_attribute(attribute:"solution", value:
"Upgrade Oracle VM VirtualBox to 4.1.34 / 4.2.26 / 4.3.14 or later as
referenced in the October 2014 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("virtualbox_installed.nasl");
  script_require_keys("installed_sw/Oracle VM VirtualBox");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'Oracle VM VirtualBox';

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

ver = install['version'];
path = install['path'];

# Note int(null) returns '0'
ver_fields = split(ver, sep:'.', keep:FALSE);
major = int(ver_fields[0]);
minor = int(ver_fields[1]);
rev = int(ver_fields[2]);

fix = '';

# Affected :
# x.x.x < 4.1.34
# 4.2.x < 4.2.26
# 4.3.x < 4.3.14
if ((major < 4) || (major == 4 && minor == 1 && rev < 34)) fix = '4.1.34';
else if (major == 4 && minor == 2 && rev < 26) fix = '4.2.26';
else if (major == 4 && minor == 3 && rev < 14) fix = '4.3.14';
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
