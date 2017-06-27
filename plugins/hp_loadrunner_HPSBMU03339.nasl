#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85767);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/11 13:32:17 $");

  script_cve_id("CVE-2015-5426");
  script_osvdb_id(126906);
  script_xref(name:"HP", value:"HPSBMU03339");
  script_xref(name:"HP", value:"SSRT102014");
  script_xref(name:"HP", value:"emr_na-c04692147");

  script_name(english:"HP LoadRunner < 12.50 Scenario File Local Code Execution");
  script_summary(english:"Checks the version of an HP LoadRunner library file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by a local code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP LoadRunner installed on the remote host is prior to
12.50. It is, therefore, affected by a local code execution
vulnerability due to an overflow condition that is triggered when
handling scenario files (.lrs). A local attacker can exploit this, via
a specially crafted scenario file, to cause a stack-based buffer
overflow, resulting in the execution of arbitrary code.");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04692147
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?68d14e81");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP LoadRunner 12.50 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:loadrunner");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_loadrunner_installed.nasl");
  script_require_keys("installed_sw/HP LoadRunner");
  script_require_ports(139, 445);

  exit(0);
}

include('global_settings.inc');
include('audit.inc');
include('misc_func.inc');
include("install_func.inc");

app_name = "HP LoadRunner";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
path    = install['path'];
verui   = install['display_version'];

fix = '12.50.0';

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Product root path     : ' + path +
      '\n  Product version       : ' + verui +
      '\n  Fixed version         : ' + fix + '\n';
    security_warning(extra:report, port:port);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, verui, path);
