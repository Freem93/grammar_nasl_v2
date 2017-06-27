#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91813);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/06/27 14:51:42 $");

  script_cve_id("CVE-2016-0916");
  script_bugtraq_id(91125);
  script_osvdb_id(139596);
  script_xref(name:"IAVA", value:"2016-A-0163");

  script_name(english:"EMC NetWorker 8.2.1.x < 8.2.2.6 / 9.0.x < 9.0.0.6 RCE");
  script_summary(english:"Checks the version of EMC NetWorker.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of EMC NetWorker installed on the remote Windows host is
8.2.1.x prior to 8.2.2.6 or 9.0.x prior to 9.0.0.6. It is, therefore, 
affected by a remote code execution vulnerability due to improper
handling of authentication. An unauthenticated, remote attacker can
exploit this to execute arbitrary commands by leveraging access to a
different NetWorker instance.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2016/Jun/att-43/ESA-2016-072.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC NetWorker 8.2.2.6 / 8.2.3.0 / 9.0.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:networker");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

# Only versions 8.2.1.0 and later are affected
if (ver_compare(ver:version, fix:'8.2.1.0', strict:FALSE) < 0)
  audit(AUDIT_INST_PATH_NOT_VULN, 'EMC NetWorker', version, path);

fix = NULL;
if (version =~ "^8\.2\." && ver_compare(ver:version, fix:'8.2.2.6', strict:FALSE) < 0)
  fix = '8.2.2.6 / 8.2.3.0';
else if (version =~ "^9\.0\." && ver_compare(ver:version, fix:'9.0.0.6', strict:FALSE) < 0)
  fix = '9.0.0.6';

if (isnull(fix))
  audit(AUDIT_INST_PATH_NOT_VULN, 'EMC NetWorker', version, path);

port = get_kb_item('SMB/transport');
if (!port) port = 445;

report =
  '\n  Path              : ' + path +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fix +
  '\n';
security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
