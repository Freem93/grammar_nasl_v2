#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78823);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/06/23 19:16:51 $");

  script_cve_id("CVE-2014-4620");
  script_bugtraq_id(70726);
  script_osvdb_id(113690);

  script_name(english:"EMC NetWorker Module for MEDITECH 3.0 Build 87 - 90 Local Information Disclosure");
  script_summary(english:"Checks the version of EMC NetWorker Module for MEDITECH.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by a local information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of EMC NetWorker (formerly Legato NetWorker) Module for
MEDITECH (NMMEDI) installed on the remote host is 3.0 build 87 - 90.
It is, therefore, affected by a local information disclosure
vulnerability due to RecoverPoint and Plink commands storing plaintext
RecoverPoint Appliance login credentials in NMMEDI log files.");
  script_set_attribute(attribute:"see_also", value:"http://support.emc.com/kb/193627");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2014/Oct/att-144/ESA-2014-087.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC NetWorker Module for MEDITECH 3.0 build 92 / 8.2 build
479 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:networker");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:meditech:meditech");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("emc_networker_installed.nasl");
  script_require_keys("installed_sw/EMC NetWorker");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

appname  = "EMC NetWorker";
modname  = 'Module for MEDITECH';
fullname = appname+" "+modname;
install  = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
version  = install[modname+' Version'];
path     = install['path'];

# Module is not installed
if (empty_or_null(version)) audit(AUDIT_NOT_INST, fullname);

if (
  ver_compare(ver:version,fix:"3.0.0.87", strict:FALSE) >= 0 &&
  ver_compare(ver:version,fix:"3.0.0.90", strict:FALSE) <= 0
)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port)) port = 445;

  if (report_verbosity > 0)
  {
    report =
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 3.0.0.92 / 8.2.0.1.479' +
        '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, fullname, version, path);
