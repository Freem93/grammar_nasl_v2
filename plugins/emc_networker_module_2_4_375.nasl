#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62946);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/15 13:39:09 $");

  script_cve_id("CVE-2012-2284", "CVE-2012-2290");
  script_bugtraq_id(55883);
  script_osvdb_id(86157, 86158);
  script_xref(name:"IAVA", value:"2012-A-0177");

  script_name(english:"EMC NetWorker Module for Microsoft Applications 2.2.1 / 2.3.x < 2.3 build 122 / 2.4.x < 2.4 build 375 Multiple Vulnerabilities");
  script_summary(english:"Checks version of EMC NetWorker Module for Microsoft Applications");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of EMC NetWorker (formerly Legato NetWorker) Module for
Microsoft Applications installed on the remote host is 2.2.1, 2.3
prior to 2.3 build 122, or 2.4 prior to 2.4 build 375. As such, it
reportedly is affected by multiple vulnerabilities, including
arbitrary code execution and an information disclosure vulnerability
that could allow an attacker the ability to obtain plaintext
credentials.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Oct/67");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC NetWorker Module for Microsoft Applications 2.3 build
122 / 2.4 build 375 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:networker_module_for_microsoft_applications");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("emc_networker_installed.nasl");
  script_require_keys("installed_sw/EMC NetWorker");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

appname  = "EMC NetWorker";
modname  = 'Module for Microsoft Applications';
fullname = appname+" "+modname;
install  = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
ver      = install[modname+' Version'];
path     = install['path'];

# Module is not installed
if(empty_or_null(ver)) audit(AUDIT_NOT_INST,fullname);

if (
   ver =~ "^2\.2\.1\." ||
  (ver =~ "^2\.3\.0\." && ver_compare(ver:ver,fix:"2.3.0.122",strict:FALSE) < 0) ||
  (ver =~ "^2\.4\.0\." && ver_compare(ver:ver,fix:"2.4.0.375",strict:FALSE) < 0)
)
{
  port = get_kb_item("SMB/transport");
  if(isnull(port)) port = 445;

  if (report_verbosity > 0)
  {
    fix = '2.3.0.122 / 2.4.0.375';
    report =
        '\n  Path              : ' + path +
        '\n  Installed version : ' + ver +
        '\n  Fixed version     : ' + fix +
        '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, fullname, ver, path);
