#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71218);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/20 14:12:05 $");

  script_cve_id("CVE-2013-7390");
  script_bugtraq_id(63784);
  script_osvdb_id(100008);
  script_xref(name:"EDB-ID", value:"29674");
  script_xref(name:"EDB-ID", value:"29812");

  script_name(english:"ManageEngine Desktop Central AgentLogUploadServlet Arbitrary File Upload");
  script_summary(english:"Checks the build number of Desktop Central.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java web application that allows for
arbitrary file uploads.");
  script_set_attribute(attribute:"description", value:
"The version of ManageEngine Desktop Central installed on the remote
host is affected by an arbitrary file upload vulnerability due to the
'AgentLogUploadServlet' script not properly sanitizing user-supplied
input to the 'filename' parameter. A remote, unauthenticated attacker
can exploit this issue to upload files containing arbitrary code and
then execute them on the remote host with NT-AUTHORITY\SYSTEM
privileges.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # http://security-assessment.com/files/documents/advisory/DesktopCentral%20Arbitrary%20File%20Upload.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f57da24d");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2013/Nov/130");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2013/Nov/152");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine Desktop Central 8.0.0 build 80293 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"ManageEngine Desktop Central 8.0.0 File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ManageEngine Desktop Central AgentLogUpload Arbitrary File Upload');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_desktop_central");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("manageengine_desktop_central_detect.nbin");
  script_require_ports("Services/www", 8020, 8383);
  script_require_keys("installed_sw/ManageEngine Desktop Central");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "ManageEngine Desktop Central";
get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_http_port(default:8020);

install = get_single_install(
  app_name            : appname,
  port                : port,
  exit_if_unknown_ver : TRUE
);

dir = install["path"];
version = install["version"];
build   = install["build"];
ismsp   = install["MSP"];
rep_version = version;
if(build !=  UNKNOWN_VER)
  rep_version += " Build "+build;
install_url =  build_url(port:port, qs:dir);

if(ismsp)
  exit(0, "The Managed Service Providers edition of Desktop Central is not known to be affected.");

if (version =~ "^8(\.|$)" && build == UNKNOWN_VER)  exit(0, "The build number of "+appname+" version " +rep_version+ " listening at " +install_url+ " could not be determined.");

if (version =~ "^8(\.|$)" && int(build) < 80293)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + rep_version +
      '\n  Fixed version     : 8 Build 80293' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, rep_version);
