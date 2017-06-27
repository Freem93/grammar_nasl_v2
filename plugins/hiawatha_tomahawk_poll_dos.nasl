#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69035);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/05/24 02:15:09 $");

  script_osvdb_id(94500);

  script_name(english:"Hiawatha Tomahawk poll DoS");
  script_summary(english:"Checks version of Hiawatha");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its server response header, the installed version of
Hiawatha is a version prior to 8.8.1.  A flaw exists in the 'poll'
function in Tomahawk that could lead to a denial of service.");
  script_set_attribute(attribute:"see_also", value:"http://www.hiawatha-webserver.org/changelog");
  script_set_attribute(attribute:"solution", value:"Upgrade to Hiawatha 8.8.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:hiawatha:webserver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("hiawatha_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Settings/ParanoidReport", "www/hiawatha");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "Hiawatha";

port = get_http_port(default:80);

install = get_install_from_kb(
  appname      : "hiawatha",
  port         : port,
  exit_on_fail : TRUE
);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = install["ver"];
if (version =~ "^8$")
  exit(1, "The version ("+version+") of " + appname + " listening on port "+port+" is not granular enough.");

if (
  version =~ "^[0-7]([^0-9]|$)" ||
  version =~ "^8\.([0-7]|8(\.0)?([^0-9.]|$))([^0-9]|$)"
)
{
  if (report_verbosity > 0)
  {
    report =
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 8.8.1' +
        '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, appname, port, version);
