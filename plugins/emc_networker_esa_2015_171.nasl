#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87309);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/06/27 14:13:07 $");

  script_cve_id("CVE-2015-6849");
  script_bugtraq_id(78519);
  script_osvdb_id(131084);

  script_name(english:"EMC NetWorker < 8.0.4.4 / 8.1.x < 8.1.3.6 / 8.2.x < 8.2.2.2 / 9.0.x < 9.0.0.2 RPC Authentication DoS");
  script_summary(english:"Checks the version of EMC NetWorker.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of EMC NetWorker installed on the remote Windows host is
prior to 8.0.4.5, 8.1.x prior to 8.1.3.6, 8.2.x prior to 8.2.2.2, or
9.0.x prior to 9.0.0.2. It is, therefore, affected by a denial of
service vulnerability due to improper handling of malformed RPC
authentication requests. An unauthenticated, remote attacker can
exploit this to crash the service.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2015/Dec/att-18/ESA-2015-171.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC NetWorker 8.0.4.5 / 8.1.3.6 / 8.2.2.2 / 9.0.0.2 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:networker");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("emc_networker_installed.nasl");
  script_require_keys("installed_sw/EMC NetWorker");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

appname  = "EMC NetWorker";
install  = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
version  = install['version'];
path     = install['path'];
build    = install['Build'];

fix = NULL;
if (ver_compare(ver:version, fix:'8.0.4.5', strict:FALSE) < 0)
  fix = '8.0.4.5';
else if (version =~ "^8\.1\." && ver_compare(ver:version, fix:'8.1.3.6', strict:FALSE) < 0)
  fix = '8.1.3.6';
else if (version =~ "^8\.2\." && ver_compare(ver:version, fix:'8.2.2.2', strict:FALSE) < 0)
  fix = '8.2.2.2';
# Only use the build number for releases that are not generally available yet.
# As of 12/9/2015 version 9 is not generally available to customers for production use
else if (version =~ "^9\.0\." && ver_compare(ver:version, fix:'9.0.0.2', strict:FALSE) < 0)
{
  if (isnull(build))
    audit(AUDIT_VER_NOT_GRANULAR, 'EMC Networker', version, path);
  else if (int(build) < 407)
  {
    version += " Build "+build; # For reporting
    fix = '9.0.0.2 Build 407';
  }
}

if (isnull(fix))
  audit(AUDIT_INST_PATH_NOT_VULN, 'EMC NetWorker', version, path);

port = get_kb_item('SMB/transport');
if (!port) port = 445;

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
