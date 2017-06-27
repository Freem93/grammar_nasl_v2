#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83032);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/12 18:38:05 $");

  script_cve_id("CVE-2015-0530");
  script_bugtraq_id(74164);
  script_osvdb_id(120793);

  script_name(english:"EMC NetWorker nsr_render_log Local Privilege Escalation");
  script_summary(english:"Checks the version of EMC NetWorker.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by a local privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The EMC NetWorker installed on the remote Windows host is a version
prior to 8.0.4.3, or version 8.1.x prior to 8.1.2.6, or 8.2.x prior to
8.2.1.2 . It is, therefore, affected by a buffer overflow flaw in the
nsr_render_log command-line interface. A local attacker can exploit
this to execute arbitrary code with root privileges on all EMC
Networker managed hosts.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2015/Apr/att-103/ESA-2015-069.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC NetWorker 8.0.4.3 / 8.1.2.6 / 8.2.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:networker");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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

fix = NULL;
if (ver_compare(ver:version, fix:'8.0.4.3', strict:FALSE) < 0)
  fix = '8.0.4.3';
else if (version =~ "^8\.1\." && ver_compare(ver:version, fix:'8.1.2.6', strict:FALSE) < 0)
  fix = '8.1.2.6';
else if (version =~ "^8\.2\." && ver_compare(ver:version, fix:'8.2.1.2', strict:FALSE) < 0)
  fix = '8.2.1.2';
else
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
