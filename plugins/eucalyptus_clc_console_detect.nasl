#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61610);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/21 15:03:34 $");

  script_name(english:"Eucalyptus Cloud Controller Console Detection");
  script_summary(english:"Looks for the Eucalyptus Cloud Controller web interface");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Eucalyptus Cloud Controller was found on the remote
host.");
  script_set_attribute(attribute:"description", value:
"The web console for Eucalyptus Cloud Controller, a Java application
that implements an interface compatible with Amazon's EC2, was found on
the remote host.");

  script_set_attribute(attribute:"see_also", value:"http://www.eucalyptus.com/eucalyptus-cloud");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:eucalyptus:eucalyptus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080, 8443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

app = "Eucalyptus Cloud Controller";

# Get the ports that webservers have been found on.
port = get_http_port(default:8443);

# Put together checks for different pages that we can scrape version
# information from.
checks = make_array();

# This covers the dashboard for 1.6 and 2.0.
regexes = make_list();
regexes[0] = make_list(
  "Eucalyptus",
  "java\.util\.HashMap",
  "java\.lang\.String"
);
regexes[1] = make_list(
  '"version","([.\\d]+)"'
);
checks["/EucalyptusWebBackend"] = regexes;

# The web interface uses the Google Web Toolkit, which cross-compiles
# Java to JavaScript. This results in an interface with very odd AJAX
# calls.
#
# All of the zeros in the payload were previously non-zero, but have
# been zeroed to be sure that they don't affect the call.
headers = make_array("Content-Type", "text/x-gwt-rpc; charset=utf-8");
payload = join(sep:"|",
  5, 0, 4,
  "",
  "00000000000000000000000000000000",
  "edu.ucsb.eucalyptus.admin.client.EucalyptusWebBackend",
  "getProperties",
  0, 0, 3, 4, 0,
  ""
);

# Find the web interface.
installs = find_install(
  appname     : "eucalyptus_clc",
  checks      : checks,
  dirs        : cgi_dirs(),
  port        : port,
  method      : "POST",
  add_headers : headers,
  data        : payload
);

if (isnull(installs))
{
  checks = make_array();

  # This covers the dashboard for 3.1.
  regexes = make_list();
  regexes[0] = make_list(
    '<title> *Eucalyptus *</title>',
    '<img[^>]*alt="Eucalyptus"[^>]*/>'
  );
  regexes[1] = make_list();
  checks["/"] = regexes;

  # Find the web interface.
  installs = find_install(
    appname     : "eucalyptus_clc",
    checks      : checks,
    dirs        : cgi_dirs(),
    port        : port
  );

  if (isnull(installs)) audit(AUDIT_NOT_DETECT, app, port);
}

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : app,
    installs     : installs,
    port         : port
  );
}

security_note(port:port, extra:report);
