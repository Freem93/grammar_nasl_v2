#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53621);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/06/17 13:25:50 $");

  script_name(english:"HP SiteScope Detection");
  script_summary(english:"Checks for the presence of HP SiteScope.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a monitoring application.");
  script_set_attribute(attribute:"description", value:
"The remote host is running HP SiteScope, an agentless network
monitoring application. HP SiteScope was formerly known as Mercury
SiteScope.");
  script_set_attribute(attribute:"solution", value:"n/a");
  # http://www8.hp.com/us/en/software-solutions/sitescope-application-monitoring/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5c69758");
  script_set_attribute(attribute:"solution",value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:sitescope");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:mercury_sitescope");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

version = UNKNOWN_VER;
md5s = make_array(
  "98f9da21cfe663ec0d9864dbc379787d", "9.53",
  "78194fda0763970d876feb00450c1645", "11.10",
  "0b814fd372de5aa942fc413f845ff890", "11.11",
  "bb9f5f017aa29048820cf65966814c77", "11.12",
  "9a7991b7f9c52cd3d6ce5097977bd557", "11.13",
  "507b2f24f7a37a47b652d6c6d336cd63", "11.20",
  "767d662b6f0ee6216bcc6fdafceacc39", "11.21",
  "a3adee3d6f5856caa6c556dbf5748de1", "11.22",
  "f6bab2488d159a3883fc4cf6bf4f557b", "11.23",
  "8ea4101849e74dd3811a2f238e8038b5", "11.24"
);

# By default, SiteScope serves on port 8080.
port = get_http_port(default:8080);

# Try to access page.
url = "/SiteScope";
res = http_send_recv3(
  method       : "GET",
  item         : url + "/",
  port         : port,
  exit_on_fail : TRUE
);

# If this is an older-style login page, it will contain the version
# number of the installation in the footer.
matches = eregmatch(string:res[2], pattern:"<small>SiteScope\s+([\d.]+)");
if (!isnull(matches))
{
  version = matches[1];
}

# 11.30 version information is on login page
#<div id="header" class="header-login">
#    SiteScope 11.30
#</div>

if(version == UNKNOWN_VER)
{
  matches = eregmatch(string:res[2], pattern:'header-login">[\\s]*SiteScope\\s*([\\d.]+)[\\s]*<');

  if (!isnull(matches))
    version = matches[1];
}

if(version == UNKNOWN_VER)
{
  gif = "images/ssimages/login_sitescope.gif";

  # Check for the SiteScope logo and CSS.
  if (
    '<img src="' + gif + '"' >!< res[2] ||
    'href="/SiteScope/static/act/stylesheets/login_hp.css"' >!< res[2]
  ) audit(AUDIT_WEB_APP_NOT_INST, "HP SiteScope", port);

  # Newer-style login pages have their version number contained
  # exclusively in a GIF. Compare the GIF to our list of MD5s so see
  # if we know which version it is.
  res = http_send_recv3(
    method       : "GET",
    item         : url + "/" + gif,
    port         : port,
    exit_on_fail : TRUE
  );

  md5 = hexstr(MD5(res[2]));
  version = md5s[md5];
}

installs = add_install(
  appname  : "sitescope",
  installs : NULL,
  port     : port,
  dir      : url,
  ver      : version
);

# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    display_name : "HP SiteScope"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
