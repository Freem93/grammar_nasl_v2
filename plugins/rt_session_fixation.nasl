#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43006);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/13 15:33:29 $");

  script_cve_id("CVE-2009-4151");
  script_bugtraq_id(37162);
  script_osvdb_id(61116);
  script_xref(name:"Secunia", value:"37546");

  script_name(english:"Request Tracker Session Fixation Vulnerability");
  script_summary(english:"Checks if Request Tracker invalidates session IDs properly.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a Perl application that is affected
by a session fixation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Best Practical Solutions Request Tracker (RT) running
on the remote web server is affected by a session fixation
vulnerability due to the application authenticating users without
invalidating their existing session ID. A remote attacker can exploit
this by tricking a user into logging in with a known session ID,
allowing the attacker to hijack the user's session.

This version of RT is reportedly affected by a different session
fixation vulnerability, though Nessus has not checked for it.");
  # http://lists.bestpractical.com/pipermail/rt-announce/2009-November/000176.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?443e08f3");
  # http://lists.bestpractical.com/pipermail/rt-announce/2009-November/000177.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?33d71852");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Request Tracker 3.8.6 / 3.6.10 or later, or apply the patch
listed in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bestpractical:rt");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("rt_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/RT");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'RT';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(app_name:app, port:port);

clear_cookiejar();
url = install['path'] + '/index.html';
full_url = build_url(qs:url, port:port);

# Try to get a session ID from an initial request
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
if ('<title>Login</title>' >!< res[2]) exit(1, 'Error getting login page on port '+port);

headers = parse_http_headers(status_line:res[0], headers:res[1]);
if (isnull(headers)) audit(AUDIT_WEB_NO_SERVER_HEADER, port);

cookie = headers['set-cookie'];
if (isnull(cookie)) exit(1, "Did not receive a session ID after 1st request.");

# Make another request, and check whether or not our initial session ID was
# invalidated
res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(1, "The web server on port "+port+" didn't respond.");
if ('<title>Login</title>' >!< res[2]) exit(1, 'Error getting login page.');

headers = parse_http_headers(status_line:res[0], headers:res[1]);
if (isnull(headers)) exit(1, 'Error parsing HTTP headers on port '+port+'.');

cookie = headers['set-cookie'];

if (isnull(cookie))
  security_warning(port);
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, full_url);
