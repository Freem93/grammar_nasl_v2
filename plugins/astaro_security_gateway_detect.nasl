#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58107);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/09 00:11:21 $");

  script_name(english:"Astaro Security Gateway Detection");
  script_summary(english:"Looks for the Astaro Security Gateway help pages");

  script_set_attribute(attribute:"synopsis", value:"A security gateway is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"Astaro Security Gateway, a suite of network / mail / web security
tools, is running on the remote host.");

  script_set_attribute(attribute:"see_also", value:"http://www.astaro.com/");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"cpe", value:"cpe:/h:astaro:security_gateway");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 4444);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

# Put together a list of directories we should check for ASG in.
dirs = cgi_dirs();

# Put together checks for different pages that we can scrape version
# information from.
checks = make_array();

# These regexes work for both v7 and v8.
regexes = make_list();
regexes[0] = make_list('<span[^>]* class="astaroproduct" *> *Astaro *Security *Gateway *</span>');
regexes[1] = make_list('<span[^>]* class="astaroversionL" *> *Version *([0-9.]*) *</span>');

# This covers v7.
checks["/ohelp/en_US/Content/master/webadmin/WebAdmin.html"] = regexes;

# This covers v8.
checks["/help/en_US/Content/master/webadmin/WebAdmin.html"] = regexes;

# Get the ports that webservers have been found on, defaulting to
# ASG's default web admin port.
port = get_http_port(default:4444);

# Find where ASG's web interface is installed.
installs = find_install(appname:"astaro_security_gateway", checks:checks, dirs:dirs, port:port);

if (isnull(installs))
  exit(0, "Astaro Security Gateway wasn't detected on port " + port + ".");

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : "Astaro Security Gateway",
    installs     : installs,
    port         : port
  );
}
security_note(port:port, extra:report);
