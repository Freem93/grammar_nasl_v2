#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if(description)
{
  script_id(48254);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/09/24 23:21:23 $");

  script_bugtraq_id(42110);

  script_name(english:"Xerver Double Slash Authentication Bypass");
  script_summary(english:"Attempts to access a protected directory.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an authentication bypass
vulnerability.");

  script_set_attribute(attribute:"description", value:
"The version of Xerver installed on the remote host is affected by an
authentication bypass vulnerability.  It is possible to access
protected web directories without authentication by prepending the
directory with an extra '/' character, as long as the directory is not
recursively protected. 

A remote, unauthenticated attacker can leverage this issue to gain
access to protected web directories.

Note that this version of Xerver is also potentially affected by
multiple other vulnerabilities, though Nessus has not tested for
these.");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e68402fd");
  script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/05");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# Xerver appears to be slow at times and we do not want to do a false negative
http_set_read_timeout(get_read_timeout() * 2);

port = get_http_port(default:80);

# Make sure this is Xerver unless we are paranoid.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner) exit(1, "Unable to get the banner from the web server on port "+port+".");
  if ("Server: Xerver/" >!< banner) exit(0, "The web server on port "+port+" does not appear to be Xerver.");
}

# We need a protected page for our test.
pages = get_kb_list("www/"+port+"/content/auth_required");
if (isnull(pages)) exit(1, "No protected pages were detected on the web server on port "+port+".");
pages = make_list(pages);

# Try to get a protected subdirectory.  This doesn't appear
# to work against the root directory
page = NULL;
for (i=0; i<max_index(pages); i++)
{
  if (pages[i] =~ '^/$') exit(0, "The web server on port "+port+" has a protected root directory and thus is not affected.");
  if (pages[i] =~ '^/[^/]+/.*')
  {
    page = pages[i];
    break;
  }
}
if (isnull(page)) exit(1, "No protected subdirectories were detected on the web server on port "+port+".");


# Try to get a protected directory
url = '/' + page;
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
if (res[0] =~ '^HTTP/1\\.1 (200|404)')
{
  if (report_verbosity > 0)
  {
    report =
      '\nNessus was able to reproduce the issue using the following URL :' +
      '\n' +
      '\n' + build_url(port:port, qs:url) + '\n';
    security_hole(port:port, extra:report);
    exit(0);
  }
}
exit(0, "The web server on port "+port+" is not affected.");
