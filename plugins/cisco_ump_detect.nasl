#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70077);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/06/15 19:31:59 $");

  script_name(english:"Cisco Unified MeetingPlace Detection");
  script_summary(english:"Checks for the Cisco Unified MeetingPlace web interface.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts web conferencing software.");
  script_set_attribute(attribute:"description", value:
"Cisco Unified MeetingPlace, a web conferencing application, is hosted
on the remote web server.");
  # http://www.cisco.com/c/en/us/products/conferencing/unified-meetingplace/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59cb29ce");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_meetingplace");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

app = "Cisco Unified MeetingPlace";

# Put together a list of directories we should check for UMP in.
# Prioritize the root directory.
dirs = list_uniq(make_list("", cgi_dirs()));

# Put together checks for different pages that we can confirm the
# name of the software from.
checks = make_nested_array(
  "/", make_nested_list(
    make_list(
      "<title> *Cisco +Unified +MeetingPlace *</title>"
    ),
    make_list(
      "<span[^>]*> *Version: +</span> *([0-9.]+) *<br/>",
      "var +m_wcVersion *= *'([0-9.]+)' *;"
    )
  ),
  "/mpweb/html/help/000/user_help/help/output/config.js", make_nested_list(
    make_list(
      'var +appTitle *= *"Cisco +Unified +MeetingPlace[^"]*" *;'
    ),
    make_list(
      'var +appTitle *= *"Cisco +Unified +MeetingPlace +Release +([0-9.]+) +Online +Help" *;'
    )
  )
);

# Get the ports that web servers have been found on.
port = get_http_port(default:80);

# Find where UMP is installed.
installs = find_install(appname:app, checks:checks, dirs:dirs, port:port);
if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, app, port);

report_installs(app_name:app,port:port);
