#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81704);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/03/10 13:35:12 $");

  script_cve_id("CVE-2014-9371");
  script_bugtraq_id(71641);
  script_osvdb_id(115792);

  script_name(english:"ManageEngine Desktop Central NativeAppServlet UDID JSON RCE");
  script_summary(english:"Checks the build number of Desktop Central MSP.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java web application that allows
execution of arbitrary code.");
  script_set_attribute(attribute:"description", value:
"The version of ManageEngine Desktop Central MSP installed on the
remote host is affected by a remote code execution vulnerability due
to a failure by NativeAppServlet to properly sanitize JSON data before
processing it. A remote attacker, using a crafted JSON object, can
exploit this to execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-420/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine Desktop Central MSP 9 Build 90075 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_desktop_central");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("manageengine_desktop_central_detect.nbin");
  script_require_ports("Services/www", 8040);
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

port = get_http_port(default:8040);

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

# Only MSP known to be affected
if(!ismsp)
  exit(0, "Only the Managed Service Providers edition of Desktop Central is known to be affected.");
else
  appname += " (MSP)";

if (version =~ "^9(\.|$)" && build == UNKNOWN_VER) 
  exit(0, "The build number of "+appname+" version " +rep_version+ " listening at " +install_url+ " could not be determined.");

# All versions < 9 Build 90075
if (
  version =~ "^9(\.|$)" && int(build) < 90075 ||
  version =~ "^[1-8](\.|$)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + rep_version + 
      '\n  Fixed version     : 9 Build 90075' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, rep_version);
