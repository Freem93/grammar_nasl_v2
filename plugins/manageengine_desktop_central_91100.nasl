#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90192);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/06/20 20:49:17 $");

  script_cve_id("CVE-2015-82001");
  script_osvdb_id(131711, 132266);
  script_xref(name:"TRA", value:"TRA-2015-07");

  script_name(english:"ManageEngine Desktop Central 8 / 9 < Build 91100 Multiple RCE");
  script_summary(english:"Checks the build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java-based web application that is
affected by multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The ManageEngine Desktop Central application running on the remote
host is version 8, or else version 9 prior to build 91100. It is,
therefore, affected by multiple remote code execution
vulnerabilities :

  - A flaw exists in the statusUpdate script due to a
    failure to properly sanitize user-supplied input to the
    'fileName' parameter. An unauthenticated, remote
    attacker can exploit this, via a crafted request to
    upload a PHP file that has multiple file extensions and
    by manipulating the 'applicationName' parameter, to make
    a direct request to the uploaded file, resulting in the
    execution of arbitrary code with NT-AUTHORITY\SYSTEM
    privileges. (CVE-2015-82001)

  - An unspecified flaw exists in various servlets that
    allow an unauthenticated, remote attacker to execute
    arbitrary code. No further details are available.
    (VulnDB 132266)

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  # https://www.manageengine.com/products/desktop-central/remote-code-execution.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?89099720");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine Desktop Central version 9 build 91100 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_desktop_central");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("manageengine_desktop_central_detect.nbin");
  script_require_ports("Services/www", 8020, 8383, 8040);
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

install_url =  build_url(port:port, qs:dir);

if (ismsp) appname += " MSP";

if (build == UNKNOWN_VER)
  exit(0, "The build number of "+appname+" version " +rep_version+ " listening at " +install_url+ " could not be determined.");
else
  rep_version += " Build " + build;

build = int(build);
if (
    (version =~ "^8(\.|$)") ||
    (version =~ "^9(\.|$)" && build < 91100)
)
{
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + rep_version +
      '\n  Fixed version     : 9 Build 91100' +
      '\n';
    security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, rep_version);
