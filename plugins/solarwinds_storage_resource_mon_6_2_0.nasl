#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86421);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/29 19:33:20 $");

  script_cve_id("CVE-2015-7838");
  script_osvdb_id(128554);
  script_xref(name:"EDB-ID", value:"34671");
  script_xref(name:"IAVA", value:"2015-A-0238");

  script_name(english:"SolarWinds Storage Resource Monitor < 6.2 ProcessFileUpload.jsp File Upload RCE");
  script_summary(english:"Checks the version of Storage Resource Monitor.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application affected by a remote code
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of SolarWinds Storage Resource
Monitor (formerly SolarWinds Storage Manager) prior to 6.2. It is,
therefore, affected by a remote code execution vulnerability due to
improper sanitization of user-uploaded files by the
ProcessFileUpload.jsp script. An unauthenticated, remote attacker can
exploit this vulnerability to upload malicious PHP scripts, resulting
in the execution of arbitrary code with the privileges of the web
server.");
  # http://www.solarwinds.com/documentation/srm/docs/releasenotes/releasenotes.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?048bbe17");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-460/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SolarWinds Storage Manager version 6.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Solarwinds Storage Manager ProcessFileUpload.jsp File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:storage_manager");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:solarwinds:storage_resource_monitor");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("solarwinds_storage_manager_installed.nbin");
  script_require_ports("installed_sw/SolarWinds Storage Manager", "installed_sw/SolarWinds Storage Resource Monitor");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

storage_res_mon = "SolarWinds Storage Resource Monitor";
storage_mgr     = "SolarWinds Storage Manager";

apps = make_list();
unaffected = make_list();

if (get_install_count(app_name:storage_res_mon) > 0) apps = make_list(apps, storage_res_mon);
if (get_install_count(app_name:storage_mgr) > 0)     apps = make_list(apps, storage_mgr);
if (empty(apps)) audit(AUDIT_NOT_INST, storage_res_mon + "/" + storage_mgr);

foreach app_name (apps)
{
  install = get_single_install(app_name:app_name, exit_if_unknown_ver:FALSE);
  path = install['path'];
  version = install['version'];
  fix = "6.2.0.749";

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
  }
  else
    unaffected = make_list(unaffected,
      "The " + app_name + " version " + version + " install under " + path  +
      " is not affected."
    );
}

if (!empty(unaffected)) exit(0, join(unaffected, sep:'\n'));
