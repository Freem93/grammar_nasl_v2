#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(91634);
  script_version ("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/06/16 17:38:37 $");

  script_name(english:"HyperText Transfer Protocol (HTTP) Redirect Information");
  script_summary(english:"Determines if the web server issues HTTP redirects.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server redirects requests to the root directory.");
 script_set_attribute(attribute:"description", value:
"The remote web server issues an HTTP redirect when requesting the root
directory of the web server.

This plugin is informational only and does not denote a security
problem.");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:
"Analyze the redirect(s) to verify that this is valid operation for
your web server and/or application.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/16");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("http_info.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
SSL = get_kb_item("Transport/SSL");

global_var report = '';
global_var report_url = build_url(qs:"/", port:port);

function report_redirects(page, port, redir_uri, resp, https)
{
  # Clean up reported URL since build_url gives us a trailing slash
  page = ereg_replace(string:page, pattern:"^/", replace:"");
  redir_uri =  ereg_replace(string:redir_uri, pattern:"^/", replace:"");

  report +=
    '\n  Request         : ' + report_url + page +
    '\n  HTTP response   : ' + resp;

  if (!empty_or_null(https))
    report +=
      '\n  Redirect to     : ' + https;
  else
    report +=
      '\n  Redirect to     : ' + report_url + redir_uri;

  if (resp =~ "30[1237]")
    report += '\n  Redirect type   : 30x redirect\n';
  else
    report += '\n  Redirect type   : meta redirect\n';

  return report;
}

# Make sure tables exist
data1 = query_scratchpad("SELECT name FROM sqlite_master where type='table' and name = 'webmirror_30x'");

data2 = query_scratchpad("SELECT name FROM sqlite_master where type='table' and name = 'webmirror_meta_redirect'");

data = NULL;

# Grab meta redirects and 30x redirects found by webmirror
if (!empty_or_null(data1) && (!empty_or_null(data2)))
  data = query_scratchpad("SELECT page, redir_uri, redir_status, redir2_https FROM `webmirror_30x` where port = ? UNION SELECT page, redir_uri, redir_status, redir2_https from `webmirror_meta_redirect` where port = ?", port, port);

else if (!empty_or_null(data1))
  data = query_scratchpad("SELECT page, redir_uri, redir_status, redir2_https FROM `webmirror_30x` WHERE port = ?", port);

else if (!empty_or_null(data2))
  data = query_scratchpad("SELECT page, redir_uri, redir_status, redir2_https FROM `webmirror_meta_redirect` WHERE port =?", port);

if (empty_or_null(data))
  exit(0, "No HTTP redirect was found on a request to the root directory on port " + port);

https = NULL;
https_uri = NULL;
no_200_resp = '\n\nNote that Nessus did not receive a 200 OK response from the'+
  '\nlast examined redirect.\n';

# Get the root directory first
foreach req (keys(data))
{
  if (data[req]['page'] == '/')
  {
    if (!empty_or_null(data[req]['redir2_https']))
      https = data[req]['redir2_https'];

    page = data[req]['page'];
    redir_uri = data[req]['redir_uri'];
    resp = data[req]['redir_status'];
    break;
  }
}
if (empty_or_null(page))
  exit(0, "No HTTP redirect was found on a request to the root directory on port " + port);

# Add initial redirect to report
report_redirects(
  page      : page,
  port      : port,
  redir_uri : redir_uri,
  resp      : resp,
  https     : https
);

# Bail out and report our root redirect is to https://
# Any redirects on the https:// port will be handled in the output for that
# port.
if (!empty_or_null(https) && port != SSL)
{
  report += no_200_resp;

  security_report_v4(
    port       : port,
    severity   : SECURITY_NOTE,
    extra      : report
  );
  exit(0);
}

# Parse the data and follow the links to build our report
page = redir_uri;

foreach req (keys(data))
{
  if (page == data[req]['page'])
  {
    if (!empty_or_null(data[req]['redir2_https']))
    {
      https_redirect = data[req]['redir2_https'];
      # Get just the path from our redirect URL
      https_uri = ereg_replace(
        pattern : "^https?://([^/]*)(/.*)*",
        replace : "\2",
        string  : https_redirect
      );
    }
    if (!empty_or_null(https_uri) && page == https_uri)
      https = https_redirect;
    redir_uri = data[req]['redir_uri'];
    if (!empty_or_null(https_uri) && redir_uri == https_uri)
      https = https_redirect;
    resp = data[req]['redir_status'];

    report_redirects(
      page      : page,
      port      : port,
      redir_uri : redir_uri,
      resp      : resp,
      https     : https
    );

    if (!empty_or_null(https) && port != SSL) break;
    page = redir_uri;
  }
   else continue;
}

if (!empty_or_null(https) && port != SSL)
{
  report += no_200_resp;

  security_report_v4(
    port       : port,
    severity   : SECURITY_NOTE,
    extra      : report
  );
  exit(0);
}

# check response on last page
res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : page,
  exit_on_fail : TRUE
);

# Bail out if our final redirect is another meta refresh
# ie: to a new domain
if (ereg(pattern:'meta.*http-equiv="refresh"', string:res[2], icase:TRUE, multiline:TRUE))
{
  report += no_200_resp;
  security_report_v4(
    port       : port,
    severity   : SECURITY_NOTE,
    extra      : report
  );
  exit(0);
}
# Make sure our reported url does not look like this
# http://foobar//blah.ext since build_url will already give us
# our trailing / ie: http://foobar/
report_page = page;
report_page = ereg_replace(string:report_page, pattern:"^/", replace:"");

report +=
  '\n  Final page      : ' + report_url + report_page +
  '\n  HTTP response   : ' + res[0] +
  '\n';

if (!empty_or_null(report))
{
  # Only set the KB items when our final page gives us a 200 OK response.
  if (res[0] =~ "^HTTP/[0-9.]+ 200 ")
  {
    set_kb_item(name:"www/"+port+"/http_redirect", value:TRUE);
    set_kb_item(name:"www/"+port+"/http_redirect_final_url", value:page);
  }
  else
    report += no_200_resp;

  security_report_v4(
    port       : port,
    severity   : SECURITY_NOTE,
    extra      : report
  );
  exit(0);
}
else exit(0, "Nessus was unable to extract information on redirects that occurred on the host on port ", port);
