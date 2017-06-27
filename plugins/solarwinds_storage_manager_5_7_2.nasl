#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77504);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/30 15:10:03 $");

  script_bugtraq_id(69438);
  script_osvdb_id(110483);

  script_name(english:"SolarWinds Storage Manager < 5.7.2 Remote Code Execution");
  script_summary(english:"Checks the version of Storage Manager.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application affected by a remote code
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of SolarWinds Storage Manager
prior to 5.7.2. It is, therefore, affected by a remote code execution
vulnerability due to a flaw in the 'AuthenticationFilter' class. A
remote, unauthenticated attacker can exploit this vulnerability to
upload malicious scripts which can then execute arbitrary code as the
user 'SYSTEM'.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-299/");
  script_set_attribute(attribute:"solution", value:"Upgrade to SolarWinds Storage Manager version 5.7.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Solarwinds Storage Manager ProcessFileUpload.jsp File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:storage_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("solarwinds_storage_manager_installed.nbin");
  script_require_keys("installed_sw/SolarWinds Storage Manager");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "SolarWinds Storage Manager";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
path = install['path'];
version = install['version'];
fix = "5.7.2";

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port)) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(extra:report, port:port);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
