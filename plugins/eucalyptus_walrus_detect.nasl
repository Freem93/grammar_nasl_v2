#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61609);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/21 15:03:34 $");

  script_name(english:"Eucalyptus Walrus Detection");
  script_summary(english:"Looks for the Eucalyptus Walrus web interface");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Eucalyptus Walrus was found on the remote host.");
  script_set_attribute(attribute:"description", value:
"Eucalyptus Walrus, a Java application that implements an interface
compatible with Amazon's S3, was found on the remote host.");
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
  script_require_ports("Services/www", 8773);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

app = "Eucalyptus Walrus";

# Get the ports that webservers have been found on.
port = get_http_port(default:8773);

# Put together checks for different pages that we can scrape
# information from.
checks = make_array();

# This covers 1.6 and 2.0.
regexes = make_list();
regexes[0] = make_list(
  "s3.amazonaws.com",
  "<Code>AccessDenied</Code>"
);
regexes[1] = make_list();
checks["/services/Walrus"] = regexes;

installs = find_install(
  appname : "eucalyptus_walrus",
  checks  : checks,
  dirs    : cgi_dirs(),
  port    : port
);

if (isnull(installs))
{
  checks = make_array();

  # This covers 3.1.
  regexes = make_list();
  regexes[0] = make_list(
    "<Code>403 Forbidden</Code>",
    "<Message>Unable to parse date.</Message>"
  );
  regexes[1] = make_list();
  checks["/services/Walrus"] = regexes;

  hdrs = make_array(
    "Authorization", "???",
    "Date", "???"
  );

  installs = find_install(
    appname     : "eucalyptus_walrus",
    checks      : checks,
    dirs        : cgi_dirs(),
    add_headers : hdrs,
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
